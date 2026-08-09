// #![allow(rust_2018_idioms)]
#![allow(
	non_snake_case,
	non_camel_case_types,
	dead_code,
	unused_variables,
	unused_braces,
	clippy::all,
	clippy::unwrap_used,
	clippy::unnecessary_debug_formatting
)]
use std::{error::Error, path::Path};

#[allow(unused)]
macro_rules! p {
	($($tokens: tt)*) => {
		println!("cargo::warning={}", format!($($tokens)*))
	}
}

type AnyResult<T> = Result<T, Box<dyn Error>>;

fn main() {
	let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
	let dir = Path::new(&dir);
	let src = dir.join("src");

	let generated_path = src.join("generated.rs");

	// let _ = std::fs::remove_file(&generated_path);

	if let Err(err) = inner(dir) {
		let err = format!("{}", err);
		let mut contents = format!("compile_error!({err:?});\n\n");
		for line in err.lines() {
			contents.push_str("// ");
			contents.push_str(line);
			contents.push_str("\n");
		}
		std::fs::write(&generated_path, contents.as_bytes()).unwrap();
	}
}

fn get_path_string(path: &Path) -> AnyResult<String> {
	let s = dunce::canonicalize(path)?
		.into_os_string()
		.into_string()
		.map_err(|_| format!("Failed to create path for {:?}", path))?;

	Ok(s)
}

fn link_ldn_lkl(ldn_lkl_dir: &Path) -> AnyResult<()> {
	const ARCHIVE: &str = "ldn-lkl.a";

	let archive = ldn_lkl_dir.join(ARCHIVE);
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
	println!("cargo:rustc-link-lib=static:+verbatim={ARCHIVE}");

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

	let ldn_lkl_include_dir = get_path_string(&ldn_lkl_include_dir)?;
	let ldn_lkl_vendor_dir = get_path_string(&ldn_lkl_vendor_dir)?;

	let bindings = builder()
		.raw_line("#![allow(non_snake_case, non_camel_case_types, dead_code, unused_variables, unused_braces, clippy::all)]\n\n")
		.header(&path)
		.clang_arg(format!("-I{}", ldn_lkl_include_dir))
		.clang_arg(format!("-I{}", ldn_lkl_vendor_dir))
		.generate()?;

	let gen_file = dir.join("src").join("generated.rs");
	bindings.write_to_file(gen_file)?;

	Ok(())
}
