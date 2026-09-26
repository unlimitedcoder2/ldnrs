use std::{error::Error, path::Path};

type AnyResult<T> = Result<T, Box<dyn Error>>;

fn main() -> AnyResult<()> {
	let dir = std::env::var("CARGO_MANIFEST_DIR")?;
	inner(Path::new(&dir))?;

	if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
		println!("cargo:rustc-link-lib=legacy_stdio_definitions");
	}

	println!("cargo:rustc-link-lib=advapi32");
	Ok(())
}

#[cfg(windows)]
fn canonicalize(path: &Path) -> std::io::Result<std::path::PathBuf> {
	dunce::canonicalize(path)
}

#[cfg(not(windows))]
fn canonicalize(path: &Path) -> std::io::Result<std::path::PathBuf> {
	std::fs::canonicalize(path)
}

fn get_path_string(path: &Path) -> AnyResult<String> {
	let s = canonicalize(path)?
		.into_os_string()
		.into_string()
		.map_err(|_| format!("Failed to create path for {}", path.display()))?;

	Ok(s)
}

fn link_ldn_lkl(ldn_lkl_dir: &Path) -> AnyResult<()> {
	let archive_name = if std::env::var("PROFILE").as_deref() == Ok("release") {
		"ldn-lkl.a"
	} else {
		"ldn-lkl-debug.a"
	};

	let archive = ldn_lkl_dir.join(archive_name);
	if !archive.is_file() {
		return Err(format!(
			"{} not found. Build it first: `cd ldnlkl && make LKL_DIR=<linux tree> -B`",
			archive.display()
		)
		.into());
	}

	println!("cargo:rerun-if-changed={}", archive.display());
	println!(
		"cargo:rustc-link-search=native={}",
		get_path_string(ldn_lkl_dir)?
	);
	println!("cargo:rustc-link-lib=static:+verbatim={archive_name}");

	for lib in ["ws2_32", "winmm"] {
		println!("cargo:rustc-link-lib={lib}");
	}

	Ok(())
}

fn inner(dir: &Path) -> AnyResult<()> {
	use bindgen::builder;

	let ldn_lkl_dir = dir.join("ldnlkl");
	let ldn_lkl_include_dir = ldn_lkl_dir.join("include").canonicalize()?;
	let ldn_lkl_vendor_dir = ldn_lkl_dir.join("vendor").canonicalize()?;

	link_ldn_lkl(&ldn_lkl_dir)?;

	let path = ldn_lkl_include_dir.join("lib.h");
	let path = get_path_string(&path)?;

	println!("cargo:rerun-if-changed={path}");

	let ldn_lkl_include_dir = get_path_string(&ldn_lkl_include_dir)?;
	let ldn_lkl_vendor_dir = get_path_string(&ldn_lkl_vendor_dir)?;

	let bindings = builder()
		.header(&path)
		.clang_arg(format!("-I{}", ldn_lkl_include_dir))
		.clang_arg(format!("-I{}", ldn_lkl_vendor_dir))
		.generate()?;

	let gen_file = Path::new(&std::env::var("OUT_DIR")?).join("generated.rs");
	bindings.write_to_file(gen_file)?;

	Ok(())
}
