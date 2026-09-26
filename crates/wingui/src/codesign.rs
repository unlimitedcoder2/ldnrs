use std::fmt::Write as _;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::null_mut;

use anyhow::Context;
use windows::Win32::Foundation::{
	CERT_E_UNTRUSTEDROOT, HANDLE, HWND, SYSTEMTIME, TRUST_E_NOSIGNATURE,
};
use windows::Win32::Security::Cryptography::Catalog::{
	CRYPTCAT_ATTR_AUTHENTICATED, CRYPTCAT_ATTR_DATAASCII, CRYPTCAT_ATTR_NAMEASCII,
	CRYPTCAT_OPEN_CREATENEW, CRYPTCAT_VERSION_1, CRYPTCATMEMBER, CryptCATAdminAcquireContext2,
	CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminReleaseContext, CryptCATClose, CryptCATOpen,
	CryptCATPersistStore, CryptCATPutAttrInfo, CryptCATPutCatAttrInfo, CryptCATPutMemberInfo,
};
use windows::Win32::Security::Cryptography::Sip::{CryptSIPCreateIndirectData, SIP_SUBJECTINFO};
use windows::Win32::Security::Cryptography::{
	ALG_ID, BCRYPT_SHA1_ALGORITHM, CALG_SHA_256, CERT_CONTEXT, CERT_CREATE_SELFSIGN_FLAGS,
	CERT_EXTENSION, CERT_EXTENSIONS, CERT_KEY_SPEC, CERT_OPEN_STORE_FLAGS,
	CERT_QUERY_ENCODING_TYPE, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_MAXIMUM_ALLOWED_FLAG,
	CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE,
	CERT_X500_NAME_STR, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_BIT_BLOB, CRYPT_ENCODE_OBJECT_FLAGS,
	CRYPT_INTEGER_BLOB, CRYPT_KEY_FLAGS, CRYPT_KEY_PROV_INFO, CRYPT_MACHINE_KEYSET, CTL_USAGE,
	CertAddCertificateContextToStore, CertCloseStore, CertCreateSelfSignCertificate,
	CertFreeCertificateContext, CertOpenStore, CertStrToNameW, CryptEncodeObjectEx, HCERTSTORE,
	MS_KEY_STORAGE_PROVIDER, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
	NCRYPT_MACHINE_KEY_FLAG, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM,
	NCryptCreatePersistedKey, NCryptDeleteKey, NCryptFinalizeKey, NCryptFreeObject,
	NCryptOpenStorageProvider, NCryptSetProperty, SIGNER_CERT, SIGNER_CERT_0,
	SIGNER_CERT_POLICY_CHAIN, SIGNER_CERT_STORE, SIGNER_CERT_STORE_INFO, SIGNER_FILE_INFO,
	SIGNER_NO_ATTR, SIGNER_SIGN_FLAGS, SIGNER_SIGNATURE_INFO, SIGNER_SIGNATURE_INFO_0,
	SIGNER_SUBJECT_FILE, SIGNER_SUBJECT_INFO, SIGNER_SUBJECT_INFO_0, SignerFreeSignerContext,
	SignerSignEx, X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, X509_KEY_USAGE,
	szOID_ENHANCED_KEY_USAGE, szOID_KEY_USAGE, szOID_OIWSEC_sha1, szOID_PKIX_KP_CODE_SIGNING,
	szOID_RSA_SHA256RSA,
};
use windows::Win32::Security::WinTrust::{
	WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
	WTD_CHOICE_CATALOG, WTD_REVOKE_NONE, WTD_STATEACTION_IGNORE, WTD_UI_NONE, WinVerifyTrust,
};
use windows::core::{self as windows_core, GUID, PCSTR, PCWSTR, PSTR, PWSTR};

#[cfg(test)]
use windows::Win32::Security::Cryptography::CERT_SYSTEM_STORE_CURRENT_USER;

use crate::ui::wide;

/// `CRYPT_SUBJTYPE_FLAT_IMAGE`: the subject interface package that hashes a file as a flat
/// blob rather than parsing it as a PE image. An INF is just bytes, so this is the one we
/// want. The `windows` crate does not define the subject-type GUIDs.
const FLAT_FILE_SIP: GUID = GUID::from_u128(0xde35_1a42_8e59_11d0_8c47_00c0_4fc2_95ee);

/// The subject type recorded *in the catalog member*, which is not the same thing as the SIP
/// used to hash the file. Driver catalogs -- Microsoft's own, and libwdi's -- all record this
/// one GUID for every member, and Windows' Authenticode catalog lookup expects it. Recording
/// the flat-file SIP here instead produces a member Windows cannot find, which it reports as
/// "No signature was present in the subject".
const CATALOG_MEMBER_SUBJECT: GUID = GUID::from_u128(0xc689_aab8_8e78_11d0_8c47_00c0_4fc2_95ee);

/// The OS versions the catalog claims to cover, in the encoding `inf2cat` uses: Vista through
/// Windows 10/11, 64-bit. Windows does not reject a package for listing an OS it is not, but a
/// missing `OSAttr` does upset some validation paths.
const OS_ATTR: &str = "2:6.0,2:6.1,2:6.2,2:6.3,2:10.0";

/// Catalog and member format version.
///
/// Version 1, not 2, and this is load-bearing. With version 2 `CryptCATPutMemberInfo` writes
/// the member's reference tag as raw hash bytes and emits an empty `CAT_MEMBERINFO2`
/// attribute; Windows' Authenticode catalog lookup then cannot find the member and reports
/// "No signature was present in the subject", which fails the install. Version 1 writes the
/// tag as the hex string and a proper `CAT_MEMBERINFO`, which is what every driver catalog on
/// the system -- Microsoft's and libwdi's alike -- actually contains.
const MEMBER_CERT_VERSION: u32 = 0x100;

/// The digest the catalog hashes members with.
///
/// SHA-1, which is deprecated everywhere else and is deliberate here. A self-signed package
/// cannot satisfy the driver policy, so it is accepted (if at all) through Windows' Authenticode
/// catalog fallback -- and that path looks a member up by its **SHA-1** tag. A SHA-256 catalog
/// is structurally fine and simply never matches: the lookup fails with "File not found in the
/// specified catalog", which surfaces as "No signature was present in the subject". libwdi uses
/// SHA-1 for the same reason. Packages signed by Microsoft use SHA-256 because they are resolved
/// by the driver path instead, which is not open to us.
const CATALOG_HASH: windows_core::PCWSTR = BCRYPT_SHA1_ALGORITHM;

/// The same digest as `CATALOG_HASH`, named the way the subject interface package wants it.
///
/// These two must agree. The member is looked up by its `CATALOG_HASH` tag and then checked
/// against the digest recorded in its `SPC_INDIRECT_DATA`; if that digest was computed with a
/// different algorithm the member is found and then rejected, with `TRUST_E_BAD_DIGEST`
/// (`0x80096010`). Only the *content* digest is pinned here -- the signature over the catalog
/// stays SHA-256.
const CATALOG_DIGEST_OID: PCSTR = szOID_OIWSEC_sha1;

const KEY_CONTAINER: &str = "ldnrs-winusb-signing";

/// Backdated and long-lived on purpose: this certificate is regenerated on every install, and
/// a narrow window would only create a way for a skewed clock to break the install.
const NOT_BEFORE: SYSTEMTIME = SYSTEMTIME {
	wYear: 2020,
	wMonth: 1,
	wDay: 1,
	wDayOfWeek: 0,
	wHour: 0,
	wMinute: 0,
	wSecond: 0,
	wMilliseconds: 0,
};

const NOT_AFTER: SYSTEMTIME = SYSTEMTIME {
	wYear: 2049,
	wMonth: 12,
	wDay: 31,
	wDayOfWeek: 0,
	wHour: 23,
	wMinute: 59,
	wSecond: 59,
	wMilliseconds: 0,
};

/// Which of the machine's two certificate hierarchies to work in.
///
/// Installing a driver means the machine's: the `PnP` installer runs as SYSTEM and never looks
/// at a user's stores. The per-user scope exists so the certificate and signing paths can be
/// exercised by the tests without elevation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
	Machine,
	#[cfg(test)]
	User,
}

impl Scope {
	const fn key_flags(self) -> NCRYPT_FLAGS {
		match self {
			Self::Machine => NCRYPT_FLAGS(NCRYPT_MACHINE_KEY_FLAG.0 | NCRYPT_OVERWRITE_KEY_FLAG.0),
			#[cfg(test)]
			Self::User => NCRYPT_OVERWRITE_KEY_FLAG,
		}
	}

	const fn provider_flags(self) -> CRYPT_KEY_FLAGS {
		match self {
			Self::Machine => CRYPT_MACHINE_KEYSET,
			#[cfg(test)]
			Self::User => CRYPT_KEY_FLAGS(0),
		}
	}

	const fn store_flags(self) -> u32 {
		match self {
			Self::Machine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
			#[cfg(test)]
			Self::User => CERT_SYSTEM_STORE_CURRENT_USER,
		}
	}
}

struct Key {
	provider: NCRYPT_PROV_HANDLE,
	handle: NCRYPT_KEY_HANDLE,
	deleted: bool,
}

impl Key {
	fn create(scope: Scope) -> anyhow::Result<Self> {
		let mut provider = NCRYPT_PROV_HANDLE(0);
		unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_KEY_STORAGE_PROVIDER, 0) }
			.context("opening the software key storage provider")?;

		let mut key = Self {
			provider,
			handle: NCRYPT_KEY_HANDLE(0),
			deleted: false,
		};

		let container = wide(KEY_CONTAINER);

		unsafe {
			NCryptCreatePersistedKey(
				provider,
				&raw mut key.handle,
				NCRYPT_RSA_ALGORITHM,
				PCWSTR(container.as_ptr()),
				CERT_KEY_SPEC(0),
				scope.key_flags(),
			)
		}
		.context("creating the signing key")?;

		let length = 2048u32.to_ne_bytes();

		unsafe {
			NCryptSetProperty(
				key.handle.into(),
				NCRYPT_LENGTH_PROPERTY,
				&length,
				NCRYPT_FLAGS(0),
			)
		}
		.context("setting the signing key length")?;

		unsafe { NCryptFinalizeKey(key.handle, NCRYPT_FLAGS(0)) }
			.context("finalizing the signing key")?;

		Ok(key)
	}

	/// Destroys the private key, leaving the certificate in the store unable to sign anything
	/// else. Call this the moment the catalog is signed.
	fn destroy(&mut self) -> anyhow::Result<()> {
		if self.deleted {
			return Ok(());
		}

		// NCryptDeleteKey frees the handle as well, so it must not be freed again.
		unsafe { NCryptDeleteKey(self.handle, 0) }.context("deleting the signing key")?;
		self.deleted = true;

		Ok(())
	}
}

impl Drop for Key {
	fn drop(&mut self) {
		let _ = self.destroy();
		let _ = unsafe { NCryptFreeObject(self.provider.into()) };
	}
}

struct Cert(*mut CERT_CONTEXT);

impl Drop for Cert {
	fn drop(&mut self) {
		let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
	}
}

fn encode(struct_type: PCSTR, value: *const core::ffi::c_void) -> anyhow::Result<Vec<u8>> {
	let mut size = 0u32;

	unsafe {
		CryptEncodeObjectEx(
			X509_ASN_ENCODING,
			struct_type,
			value,
			CRYPT_ENCODE_OBJECT_FLAGS::default(),
			None,
			None,
			&raw mut size,
		)
	}
	.context("sizing a certificate extension")?;

	let mut encoded = vec![0u8; usize::try_from(size)?];

	unsafe {
		CryptEncodeObjectEx(
			X509_ASN_ENCODING,
			struct_type,
			value,
			CRYPT_ENCODE_OBJECT_FLAGS::default(),
			None,
			Some(encoded.as_mut_ptr().cast()),
			&raw mut size,
		)
	}
	.context("encoding a certificate extension")?;

	encoded.truncate(usize::try_from(size)?);

	Ok(encoded)
}

fn encode_name(subject: &str) -> anyhow::Result<Vec<u8>> {
	let subject = wide(subject);
	let mut size = 0u32;

	unsafe {
		CertStrToNameW(
			X509_ASN_ENCODING,
			PCWSTR(subject.as_ptr()),
			CERT_X500_NAME_STR,
			None,
			None,
			&raw mut size,
			None,
		)
	}
	.context("sizing the certificate subject name")?;

	let mut encoded = vec![0u8; usize::try_from(size)?];

	unsafe {
		CertStrToNameW(
			X509_ASN_ENCODING,
			PCWSTR(subject.as_ptr()),
			CERT_X500_NAME_STR,
			None,
			Some(encoded.as_mut_ptr()),
			&raw mut size,
			None,
		)
	}
	.context("encoding the certificate subject name")?;

	encoded.truncate(usize::try_from(size)?);

	Ok(encoded)
}

/// Two extensions, both of which Authenticode looks at: the code-signing EKU, which is what
/// makes this a signing certificate rather than a generic one, and a key usage of
/// `digitalSignature`. No basic constraints, matching what libwdi produces -- the certificate
/// is its own trust anchor and is never used to issue anything.
fn self_signed_cert(subject: &str, key: &Key, scope: Scope) -> anyhow::Result<Cert> {
	let mut name = encode_name(subject)?;

	let mut code_signing = [PSTR(szOID_PKIX_KP_CODE_SIGNING.0.cast_mut())];
	let usage = CTL_USAGE {
		cUsageIdentifier: 1,
		rgpszUsageIdentifier: code_signing.as_mut_ptr(),
	};
	let mut eku = encode(X509_ENHANCED_KEY_USAGE, core::ptr::from_ref(&usage).cast())?;

	// One bit, `digitalSignature`, so seven of the eight bits in the byte are unused.
	let mut usage_bits = [0x80u8];
	let key_usage = CRYPT_BIT_BLOB {
		cbData: 1,
		pbData: usage_bits.as_mut_ptr(),
		cUnusedBits: 7,
	};
	let mut key_usage = encode(X509_KEY_USAGE, core::ptr::from_ref(&key_usage).cast())?;

	let mut extensions = [
		CERT_EXTENSION {
			pszObjId: PSTR(szOID_ENHANCED_KEY_USAGE.0.cast_mut()),
			fCritical: false.into(),
			Value: CRYPT_INTEGER_BLOB {
				cbData: u32::try_from(eku.len())?,
				pbData: eku.as_mut_ptr(),
			},
		},
		CERT_EXTENSION {
			pszObjId: PSTR(szOID_KEY_USAGE.0.cast_mut()),
			fCritical: false.into(),
			Value: CRYPT_INTEGER_BLOB {
				cbData: u32::try_from(key_usage.len())?,
				pbData: key_usage.as_mut_ptr(),
			},
		},
	];

	let extensions = CERT_EXTENSIONS {
		cExtension: u32::try_from(extensions.len())?,
		rgExtension: extensions.as_mut_ptr(),
	};

	let name = CRYPT_INTEGER_BLOB {
		cbData: u32::try_from(name.len())?,
		pbData: name.as_mut_ptr(),
	};

	let algorithm = CRYPT_ALGORITHM_IDENTIFIER {
		pszObjId: PSTR(szOID_RSA_SHA256RSA.0.cast_mut()),
		Parameters: CRYPT_INTEGER_BLOB::default(),
	};

	// Points the certificate at the key we just generated. dwProvType 0 and dwKeySpec 0 mean
	// CNG rather than a legacy CryptoAPI container.
	let mut container = wide(KEY_CONTAINER);
	let mut provider = wide("Microsoft Software Key Storage Provider");
	let provider_info = CRYPT_KEY_PROV_INFO {
		pwszContainerName: PWSTR(container.as_mut_ptr()),
		pwszProvName: PWSTR(provider.as_mut_ptr()),
		dwProvType: 0,
		dwFlags: scope.provider_flags(),
		cProvParam: 0,
		rgProvParam: null_mut(),
		dwKeySpec: 0,
	};

	// The key is reached through the provider info above, not passed directly.
	let _ = key;

	let not_before = NOT_BEFORE;
	let not_after = NOT_AFTER;

	let cert = unsafe {
		CertCreateSelfSignCertificate(
			None,
			&raw const name,
			CERT_CREATE_SELFSIGN_FLAGS(0),
			Some(&raw const provider_info),
			Some(&raw const algorithm),
			Some(&raw const not_before),
			Some(&raw const not_after),
			Some(&raw const extensions),
		)
	};

	if cert.is_null() {
		return Err(windows::core::Error::from_thread())
			.context("creating the self-signed certificate");
	}

	Ok(Cert(cert))
}

/// `Root` is what makes the signature chain verify at all; `TrustedPublisher` is what stops
/// Windows asking the user whether they want to trust the publisher. Both need elevation.
/// Neither prompts: the confirmation dialog people associate with installing a root belongs
/// to the *user's* root store, not the machine's.
fn add_to_store(cert: &Cert, store: &str, scope: Scope) -> anyhow::Result<()> {
	let name = wide(store);

	let handle = unsafe {
		CertOpenStore(
			CERT_STORE_PROV_SYSTEM_W,
			CERT_QUERY_ENCODING_TYPE(0),
			None,
			CERT_OPEN_STORE_FLAGS(
				scope.store_flags()
					| CERT_STORE_OPEN_EXISTING_FLAG.0
					| CERT_STORE_MAXIMUM_ALLOWED_FLAG.0,
			),
			Some(name.as_ptr().cast()),
		)
	}
	.with_context(|| format!("opening the {store} certificate store"))?;

	let added = unsafe {
		CertAddCertificateContextToStore(
			Some(handle),
			cert.0,
			CERT_STORE_ADD_REPLACE_EXISTING,
			None,
		)
	};

	let _ = unsafe { CertCloseStore(Some(handle), 0) };

	added.with_context(|| format!("adding the certificate to the {store} store"))
}

struct Catalog(HANDLE);

impl Drop for Catalog {
	fn drop(&mut self) {
		let _ = unsafe { CryptCATClose(self.0) };
	}
}

fn put_member_attr(
	catalog: &Catalog,
	member: *mut CRYPTCATMEMBER,
	tag: &str,
	value: &str,
) -> anyhow::Result<()> {
	let tag_w = wide(tag);
	let mut value_w = wide(value);
	let bytes = u32::try_from(
		value_w
			.len()
			.checked_mul(size_of::<u16>())
			.context("attribute value is too long")?,
	)?;

	let attr = unsafe {
		CryptCATPutAttrInfo(
			catalog.0,
			member,
			PCWSTR(tag_w.as_ptr()),
			CRYPTCAT_ATTR_NAMEASCII.0 | CRYPTCAT_ATTR_DATAASCII.0 | CRYPTCAT_ATTR_AUTHENTICATED.0,
			bytes,
			value_w.as_mut_ptr().cast(),
		)
	};

	if attr.is_null() {
		return Err(windows::core::Error::from_thread())
			.with_context(|| format!("adding the {tag} attribute"));
	}

	Ok(())
}

fn put_catalog_attr(catalog: &Catalog, tag: &str, value: &str) -> anyhow::Result<()> {
	let tag_w = wide(tag);
	let mut value_w = wide(value);
	let bytes = u32::try_from(
		value_w
			.len()
			.checked_mul(size_of::<u16>())
			.context("attribute value is too long")?,
	)?;

	let attr = unsafe {
		CryptCATPutCatAttrInfo(
			catalog.0,
			PCWSTR(tag_w.as_ptr()),
			CRYPTCAT_ATTR_NAMEASCII.0 | CRYPTCAT_ATTR_DATAASCII.0 | CRYPTCAT_ATTR_AUTHENTICATED.0,
			bytes,
			value_w.as_mut_ptr().cast(),
		)
	};

	if attr.is_null() {
		return Err(windows::core::Error::from_thread())
			.with_context(|| format!("adding the {tag} catalog attribute"));
	}

	Ok(())
}

/// A catalog member is a hash plus the attributes describing what was hashed. The hash has to
/// arrive as a `SPC_INDIRECT_DATA` blob built by the subject interface package for the file's
/// type -- for an INF that is the flat-file SIP, which hashes the bytes as they sit.
fn add_member(catalog: &Catalog, admin: isize, dir: &Path, name: &str) -> anyhow::Result<()> {
	let path = dir.join(name);
	let file = File::open(&path).with_context(|| format!("opening {name} to hash it"))?;
	let handle = HANDLE(file.as_raw_handle());

	let mut size = 0u32;
	unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &raw mut size, None, None) }
		.with_context(|| format!("sizing the hash of {name}"))?;

	let mut hash = vec![0u8; usize::try_from(size)?];
	unsafe {
		CryptCATAdminCalcHashFromFileHandle2(
			admin,
			handle,
			&raw mut size,
			Some(hash.as_mut_ptr()),
			None,
		)
	}
	.with_context(|| format!("hashing {name}"))?;

	// The reference tag of a member is its hash in uppercase hex; that is how the PnP
	// installer looks a file up in a catalog.
	let mut tag = String::new();
	for byte in &hash {
		write!(tag, "{byte:02X}")?;
	}

	let mut subject_type = FLAT_FILE_SIP;
	let full_path = wide(
		path.to_str()
			.context("driver package path is not valid unicode")?,
	);

	let mut subject = SIP_SUBJECTINFO {
		cbSize: u32::try_from(size_of::<SIP_SUBJECTINFO>())?,
		pgSubjectType: &raw mut subject_type,
		hFile: handle,
		pwsFileName: PCWSTR(full_path.as_ptr()),
		DigestAlgorithm: CRYPT_ALGORITHM_IDENTIFIER {
			pszObjId: PSTR(CATALOG_DIGEST_OID.0.cast_mut()),
			Parameters: CRYPT_INTEGER_BLOB::default(),
		},
		..Default::default()
	};

	let mut indirect_size = 0u32;
	unsafe { CryptSIPCreateIndirectData(&raw mut subject, &raw mut indirect_size, null_mut()) }
		.with_context(|| format!("sizing the indirect data for {name}"))?;

	// The SIP writes a struct followed by the data its pointers refer to, so the buffer has to
	// be aligned for the struct. A Vec<u64> gives eight-byte alignment for free.
	let words = usize::try_from(indirect_size)?.div_ceil(size_of::<u64>());
	let mut buffer = vec![0u64; words];
	let indirect = buffer.as_mut_ptr().cast();

	unsafe { CryptSIPCreateIndirectData(&raw mut subject, &raw mut indirect_size, indirect) }
		.with_context(|| format!("building the indirect data for {name}"))?;

	let name_w = wide(name);
	let tag_w = wide(&tag);
	let mut member_subject = CATALOG_MEMBER_SUBJECT;

	let member = unsafe {
		CryptCATPutMemberInfo(
			catalog.0,
			PCWSTR(name_w.as_ptr()),
			PCWSTR(tag_w.as_ptr()),
			&raw mut member_subject,
			MEMBER_CERT_VERSION,
			indirect_size,
			indirect.cast(),
		)
	};

	if member.is_null() {
		return Err(windows::core::Error::from_thread())
			.with_context(|| format!("adding {name} to the catalog"));
	}

	put_member_attr(catalog, member, "File", name)?;
	put_member_attr(catalog, member, "OSAttr", OS_ATTR)?;

	Ok(())
}

fn build_catalog(
	dir: &Path,
	catalog_name: &str,
	files: &[&str],
	hardware_id: &str,
) -> anyhow::Result<()> {
	let path = dir.join(catalog_name);

	// CryptCATOpen with CREATENEW refuses to overwrite.
	let _ = std::fs::remove_file(&path);

	let mut admin = 0isize;
	unsafe { CryptCATAdminAcquireContext2(&raw mut admin, None, CATALOG_HASH, None, None) }
		.context("acquiring a catalog context")?;

	let result = (|| {
		let path_w = wide(path.to_str().context("catalog path is not valid unicode")?);

		let handle = unsafe {
			CryptCATOpen(
				PCWSTR(path_w.as_ptr()),
				CRYPTCAT_OPEN_CREATENEW,
				0,
				CRYPTCAT_VERSION_1,
				0,
			)
		};

		if handle.is_invalid() {
			return Err(windows::core::Error::from_thread()).context("creating the catalog");
		}

		let catalog = Catalog(handle);

		put_catalog_attr(&catalog, "HWID1", hardware_id)?;
		put_catalog_attr(&catalog, "OSAttr", OS_ATTR)?;

		for file in files {
			add_member(&catalog, admin, dir, file)?;
		}

		unsafe { CryptCATPersistStore(catalog.0) }.context("writing the catalog")?;

		Ok(())
	})();

	let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };

	result
}

fn sign_catalog(path: &Path, cert: &Cert) -> anyhow::Result<()> {
	let path_w = wide(path.to_str().context("catalog path is not valid unicode")?);

	let mut file_info = SIGNER_FILE_INFO {
		cbSize: u32::try_from(size_of::<SIGNER_FILE_INFO>())?,
		pwszFileName: PCWSTR(path_w.as_ptr()),
		hFile: HANDLE(null_mut()),
	};

	let mut index = 0u32;
	let subject = SIGNER_SUBJECT_INFO {
		cbSize: u32::try_from(size_of::<SIGNER_SUBJECT_INFO>())?,
		pdwIndex: &raw mut index,
		dwSubjectChoice: SIGNER_SUBJECT_FILE,
		Anonymous: SIGNER_SUBJECT_INFO_0 {
			pSignerFileInfo: &raw mut file_info,
		},
	};

	let mut store_info = SIGNER_CERT_STORE_INFO {
		cbSize: u32::try_from(size_of::<SIGNER_CERT_STORE_INFO>())?,
		pSigningCert: cert.0,
		dwCertPolicy: SIGNER_CERT_POLICY_CHAIN,
		hCertStore: HCERTSTORE::default(),
	};

	let signer_cert = SIGNER_CERT {
		cbSize: u32::try_from(size_of::<SIGNER_CERT>())?,
		dwCertChoice: SIGNER_CERT_STORE,
		Anonymous: SIGNER_CERT_0 {
			pCertStoreInfo: &raw mut store_info,
		},
		hwnd: HWND(null_mut()),
	};

	let signature_info = SIGNER_SIGNATURE_INFO {
		cbSize: u32::try_from(size_of::<SIGNER_SIGNATURE_INFO>())?,
		algidHash: ALG_ID(CALG_SHA_256.0),
		dwAttrChoice: SIGNER_NO_ATTR,
		Anonymous: SIGNER_SIGNATURE_INFO_0 {
			pAttrAuthcode: null_mut(),
		},
		psAuthenticated: null_mut(),
		psUnauthenticated: null_mut(),
	};

	let context = unsafe {
		SignerSignEx(
			SIGNER_SIGN_FLAGS(0),
			&raw const subject,
			&raw const signer_cert,
			&raw const signature_info,
			None,
			PCWSTR::null(),
			None,
			None,
		)
	}
	.context("signing the catalog")?;

	if !context.is_null() {
		let _ = unsafe { SignerFreeSignerContext(context) };
	}

	Ok(())
}

fn verify_for_driver_install(dir: &Path, inf_name: &str, catalog_name: &str) -> anyhow::Result<()> {
	let catalog_path = dir.join(catalog_name);
	let member_path = dir.join(inf_name);

	let mut admin = 0isize;
	unsafe { CryptCATAdminAcquireContext2(&raw mut admin, None, CATALOG_HASH, None, None) }
		.context("acquiring a catalog context to verify the package")?;

	let result = (|| {
		let file = File::open(&member_path).context("reopening the inf to verify it")?;
		let handle = HANDLE(file.as_raw_handle());

		let mut size = 0u32;
		unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &raw mut size, None, None) }
			.context("sizing the hash of the inf")?;
		let mut hash = vec![0u8; usize::try_from(size)?];
		unsafe {
			CryptCATAdminCalcHashFromFileHandle2(
				admin,
				handle,
				&raw mut size,
				Some(hash.as_mut_ptr()),
				None,
			)
		}
		.context("hashing the inf")?;

		let mut tag = String::new();
		for byte in &hash {
			write!(tag, "{byte:02X}")?;
		}

		let catalog_w = wide(
			catalog_path
				.to_str()
				.context("catalog path is not valid unicode")?,
		);
		let member_w = wide(
			member_path
				.to_str()
				.context("inf path is not valid unicode")?,
		);
		let tag_w = wide(&tag);

		let mut catalog_info = WINTRUST_CATALOG_INFO {
			cbStruct: u32::try_from(size_of::<WINTRUST_CATALOG_INFO>())?,
			pcwszCatalogFilePath: PCWSTR(catalog_w.as_ptr()),
			pcwszMemberTag: PCWSTR(tag_w.as_ptr()),
			pcwszMemberFilePath: PCWSTR(member_w.as_ptr()),
			hMemberFile: handle,
			pbCalculatedFileHash: hash.as_mut_ptr(),
			cbCalculatedFileHash: size,
			hCatAdmin: admin,
			..Default::default()
		};

		let mut trust = WINTRUST_DATA {
			cbStruct: u32::try_from(size_of::<WINTRUST_DATA>())?,
			dwUIChoice: WTD_UI_NONE,
			fdwRevocationChecks: WTD_REVOKE_NONE,
			dwUnionChoice: WTD_CHOICE_CATALOG,
			Anonymous: WINTRUST_DATA_0 {
				pCatalog: &raw mut catalog_info,
			},
			dwStateAction: WTD_STATEACTION_IGNORE,
			..Default::default()
		};

		let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		let status =
			unsafe { WinVerifyTrust(HWND(null_mut()), &raw mut action, (&raw mut trust).cast()) };

		if status == 0 {
			return Ok(());
		}

		if status == TRUST_E_NOSIGNATURE.0 {
			anyhow::bail!(
				"Windows cannot find the inf inside the catalog that was just built for it.\r\n\r\n\
				 That is a defect in the catalog rather than a problem with this machine."
			);
		}

		if status == CERT_E_UNTRUSTEDROOT.0 {
			anyhow::bail!(
				"The signing certificate was not trusted when the package was checked.\r\n\r\nIt \
				 should have been added to this machine's Root and Trusted Publishers stores a \
				 moment ago, so this normally means that step did not take effect. Running the \
				 wizard as administrator and trying again usually fixes it."
			);
		}

		anyhow::bail!("Windows rejected the signed package (0x{status:08X}).");
	})();

	let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };

	result
}

pub fn sign_package(
	dir: &Path,
	inf_name: &str,
	catalog_name: &str,
	hardware_id: &str,
) -> anyhow::Result<()> {
	let mut key = Key::create(Scope::Machine)?;

	let cert = self_signed_cert(&certificate_subject(hardware_id), &key, Scope::Machine)?;

	add_to_store(&cert, "Root", Scope::Machine)?;
	add_to_store(&cert, "TrustedPublisher", Scope::Machine)?;

	build_catalog(dir, catalog_name, &[inf_name], hardware_id)?;
	sign_catalog(&dir.join(catalog_name), &cert)?;

	key.destroy()?;

	verify_for_driver_install(dir, inf_name, catalog_name)?;

	Ok(())
}

#[must_use]
pub fn certificate_subject(hardware_id: &str) -> String {
	format!("CN={hardware_id} (ldnrs self-signed)")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
	use windows::Win32::Security::Cryptography::Catalog::{
		CRYPTCAT_OPEN_EXISTING, CryptCATEnumerateMember,
	};
	use windows::Win32::Security::Cryptography::{
		CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
		CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CertEnumCertificatesInStore,
		CertGetNameStringW, CryptQueryObject,
	};

	use super::*;

	#[test]
	fn flat_file_sip_guid_matches_crypt_subjtype_flat_image() {
		assert_eq!(
			format!("{FLAT_FILE_SIP:?}").to_uppercase(),
			"DE351A42-8E59-11D0-8C47-00C04FC295EE"
		);
	}

	#[test]
	fn builds_a_catalog_wintrust_can_read_back() {
		let dir = std::env::temp_dir().join("ldnrs-codesign-test");
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).expect("a temp directory");

		let inf = "ldnrs_winusb.inf";
		std::fs::write(dir.join(inf), b"; not a real inf, just bytes to hash\r\n")
			.expect("writing the test inf");

		build_catalog(&dir, "ldnrs_winusb.cat", &[inf], "USB\\VID_0000&PID_0000")
			.expect("building the catalog");

		let path = dir.join("ldnrs_winusb.cat");
		let built = std::fs::metadata(&path).expect("the catalog should exist");
		assert!(built.len() > 0, "the catalog should not be empty");

		let mut admin = 0isize;
		unsafe { CryptCATAdminAcquireContext2(&raw mut admin, None, CATALOG_HASH, None, None) }
			.expect("a catalog context");

		let file = File::open(dir.join(inf)).expect("reopening the inf");
		let handle = HANDLE(file.as_raw_handle());
		let mut size = 0u32;
		unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, handle, &raw mut size, None, None) }
			.expect("sizing the hash");
		let mut hash = vec![0u8; usize::try_from(size).unwrap()];
		unsafe {
			CryptCATAdminCalcHashFromFileHandle2(
				admin,
				handle,
				&raw mut size,
				Some(hash.as_mut_ptr()),
				None,
			)
		}
		.expect("hashing the inf");

		let mut expected = String::new();
		for byte in &hash {
			write!(expected, "{byte:02X}").expect("writing hex");
		}

		let path_w = wide(path.to_str().expect("a unicode path"));
		let reopened = unsafe {
			CryptCATOpen(
				PCWSTR(path_w.as_ptr()),
				CRYPTCAT_OPEN_EXISTING,
				0,
				CRYPTCAT_VERSION_1,
				0,
			)
		};
		assert!(!reopened.is_invalid(), "wintrust should reopen the catalog");
		let reopened = Catalog(reopened);

		let mut tags = Vec::new();
		let mut member = std::ptr::null_mut();
		loop {
			member = unsafe { CryptCATEnumerateMember(reopened.0, member) };
			if member.is_null() {
				break;
			}
			let tag = unsafe { (*member).pwszReferenceTag };
			tags.push(unsafe { tag.to_string() }.expect("a unicode reference tag"));
		}

		let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };

		assert_eq!(
			tags,
			vec![expected],
			"the catalog should contain exactly the inf, tagged with its hash"
		);

		assert!(
			tags.first().is_some_and(|tag| tag.len() == 40
				&& tag
					.chars()
					.all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())),
			"the member tag must be the uppercase SHA-1 hex string, got {tags:?}"
		);
	}

	#[test]
	fn signs_a_catalog_with_a_self_signed_certificate() {
		let dir = std::env::temp_dir().join("ldnrs-codesign-sign-test");
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).expect("a temp directory");

		let inf = "ldnrs_winusb.inf";
		std::fs::write(dir.join(inf), b"; bytes to hash\r\n").expect("writing the test inf");
		build_catalog(&dir, "ldnrs_winusb.cat", &[inf], "USB\\VID_0000&PID_0000")
			.expect("building the catalog");

		let path = dir.join("ldnrs_winusb.cat");
		let unsigned = std::fs::metadata(&path).expect("the catalog").len();

		let subject = certificate_subject("USB\\VID_0000&PID_0000");

		{
			let mut key = Key::create(Scope::User).expect("generating a signing key");
			let cert =
				self_signed_cert(&subject, &key, Scope::User).expect("creating the certificate");

			sign_catalog(&path, &cert).expect("signing the catalog");

			key.destroy().expect("destroying the private key");
		}

		let signed = std::fs::metadata(&path).expect("the catalog").len();
		assert!(
			signed > unsigned,
			"signing should have grown the catalog ({unsigned} -> {signed})"
		);

		let path_w = wide(path.to_str().expect("a unicode path"));
		let mut store = HCERTSTORE::default();

		unsafe {
			CryptQueryObject(
				CERT_QUERY_OBJECT_FILE,
				path_w.as_ptr().cast(),
				CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
				CERT_QUERY_FORMAT_FLAG_BINARY,
				0,
				None,
				None,
				None,
				Some(&raw mut store),
				None,
				None,
			)
		}
		.expect("the signed catalog should parse as a PKCS7 signed message");

		let mut subjects = Vec::new();
		let mut context: *mut CERT_CONTEXT = std::ptr::null_mut();
		loop {
			context = unsafe { CertEnumCertificatesInStore(store, Some(context)) };
			if context.is_null() {
				break;
			}

			let len = unsafe {
				CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None)
			};
			let mut name = vec![0u16; usize::try_from(len).unwrap()];
			unsafe {
				CertGetNameStringW(
					context,
					CERT_NAME_SIMPLE_DISPLAY_TYPE,
					0,
					None,
					Some(name.as_mut_slice()),
				)
			};
			subjects.push(
				String::from_utf16_lossy(&name)
					.trim_end_matches('\0')
					.to_owned(),
			);
		}

		let _ = unsafe { CertCloseStore(Some(store), 0) };

		let expected = subject.trim_start_matches("CN=");
		assert_eq!(
			subjects,
			vec![expected.to_owned()],
			"the catalog should carry exactly our self-signed certificate"
		);
	}

	#[test]
	fn encodes_a_subject_name() {
		let encoded = encode_name("CN=ldnrs test").expect("a CN should encode");
		assert!(!encoded.is_empty());
	}
}
