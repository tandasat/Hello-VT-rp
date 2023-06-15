use crate::{copy_artifacts_to, DynError, TestVm, UnixCommand};
use std::{
    env, fmt,
    io::{BufRead, BufReader},
    path::Path,
    process::Stdio,
    sync::mpsc::channel,
    thread,
    time::{Duration, SystemTime},
};

pub(crate) struct Bochs {
    pub(crate) cpu: Cpu,
}

impl TestVm for Bochs {
    fn deploy(&self, release: bool) -> Result<(), DynError> {
        copy_artifacts_to("./tests/samples/bochs_disk.img", release)
    }

    fn run(&self) -> Result<(), DynError> {
        // Start a threads that tries to connect to Bochs in an infinite loop.
        thread::spawn(|| loop {
            let client = if env::consts::OS == "macos" {
                "nc"
            } else {
                "telnet"
            };
            let output = UnixCommand::new(client)
                .args(["localhost", "14449"])
                .stdout(Stdio::piped())
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();

            let now = SystemTime::now();

            let reader = BufReader::new(output.stdout.unwrap());
            reader
                .lines()
                .map_while(std::result::Result::ok)
                .for_each(|line| {
                    println!("{:>4}: {line}\r", now.elapsed().unwrap_or_default().as_secs());
                });

            thread::sleep(Duration::from_secs(1));
        });

        let cpu_type = self.cpu.to_string().to_lowercase();
        thread::spawn(move || {
            // Start Bochs from the "tests" directory in background.
            static DBG_CMD: &str = "./bochs/dbg_command.txt";
            //let bochs = if cfg!(target_os = "windows") {
            //    r"C:\class\Bochs\bochs\obj-release\bochs.exe"
            //} else {
            //    "bochs"
            //};
            let bxrc = format!("./bochs/{}_{cpu_type}.bxrc", "linux");
            let output = UnixCommand::new("bochs")
                .args(["-q", "-unlock", "-rc", DBG_CMD, "-f", &bxrc])
                .current_dir(Path::new("./tests"))
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            // Read and print stdout as they come in. This does not return.
            let reader = BufReader::new(output.stdout.unwrap());
            reader
                .lines()
                .map_while(std::result::Result::ok)
                .for_each(|line| println!("{line}\r"));
        });

        let (tx, rx) = channel();
        ctrlc::set_handler(move || tx.send(()).unwrap())?;
        rx.recv()?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum Cpu {
    Intel,
    Amd,
}
impl fmt::Display for Cpu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
