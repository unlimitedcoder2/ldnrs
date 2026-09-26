use ldn::Lkl;

pub struct App {
	pub lkl: Lkl,
}

impl App {
	pub fn new() -> Self {
		let lkl = Lkl::new();
		Self { lkl }
	}
}
