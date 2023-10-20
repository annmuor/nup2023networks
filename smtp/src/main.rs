#[macro_use]
extern crate log;

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_std::task;
use samotop::mail::{Builder, DebugService, MailDir, Name};
use samotop::server::TcpServer;
use samotop::smtp::{Esmtp, Prudence, SmtpParser};
use structopt::StructOpt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result<()> {
    env_logger::init();
    task::block_on(main_fut())
}

async fn main_fut() -> Result<()> {
    let setup = Setup::from_args();

    let service = Builder
        + Name::new(setup.name())
        + DebugService::default()
        + Esmtp.with(SmtpParser)
        + setup.prudence()
        + MailDir::new(setup.mail_dir())?;
    TcpServer::on_all(setup.ports())
        .serve(service.build())
        .await
}

pub struct Setup {
    opt: Opt,
}

impl Setup {
    pub fn from_args() -> Setup {
        Setup {
            opt: Opt::from_args(),
        }
    }

    pub fn prudence(&self) -> Prudence {
        let mut prudence = Prudence::default();
        if let Some(delay) = self.opt.prudent_banner_delay {
            prudence = prudence.with_banner_delay(Duration::from_millis(delay));
        }
        if let Some(timeout) = self.opt.prudent_command_timeout {
            prudence = prudence.with_read_timeout(Duration::from_millis(timeout));
        }
        prudence
    }

    /// Get all TCP ports to serve the service on
    pub fn ports(&self) -> Vec<String> {
        if self.opt.ports.is_empty() {
            vec!["localhost:25".to_owned()]
        } else {
            self.opt.ports.to_vec()
        }
    }

    /// Mail service, use a given name or default to host name
    pub fn name(&self) -> String {
        match &self.opt.name {
            None => match hostname::get() {
                Err(e) => {
                    warn!("Unable to get hostname, using default. {}", e);
                    "Samotop".into()
                }
                Ok(name) => match name.into_string() {
                    Err(e) => {
                        warn!("Unable to use hostname, using default. {:?}", e);
                        "Samotop".into()
                    }
                    Ok(name) => name,
                },
            },
            Some(name) => name.clone(),
        }
    }

    pub fn mail_dir(&self) -> PathBuf {
        self.absolute_path(&self.opt.mail_dir)
    }

    fn absolute_path(&self, path: impl AsRef<Path>) -> PathBuf {
        if path.as_ref().is_absolute() {
            path.as_ref().to_owned()
        } else {
            self.opt.base_dir.join(path)
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "samotop")]
struct Opt {
    /// SMTP server address:port,
    /// such as 127.0.0.1:25 or localhost:12345.
    /// The option can be set multiple times and
    /// the server will start on all given ports.
    /// If no ports are given, the default is to
    /// start on localhost:25.
    #[structopt(short = "p", long = "port", name = "port")]
    ports: Vec<String>,

    /// Use the given name in SMTP greetings, or if absent, use hostname.
    #[structopt(short = "n", long = "name", name = "SMTP service name")]
    name: Option<String>,

    /// Where to store incoming mail?
    /// If a relative path is given, it will be relative to base-dir.
    #[structopt(
    short = "m",
    long = "mail-dir",
    name = "mail dir path",
    default_value = "inmail"
    )]
    mail_dir: PathBuf,

    /// What is the base dir for other relative paths?
    #[structopt(
    short = "b",
    long = "base-dir",
    name = "base dir path",
    default_value = "."
    )]
    base_dir: PathBuf,

    /// Should we enforce prudent banner deleay?
    /// Delay is in miliseconds.
    #[structopt(long = "banner_delay", name = "delay")]
    prudent_banner_delay: Option<u64>,

    /// Should we enforce prudent command timeout?
    /// Timeout is in miliseconds.
    #[structopt(long = "command_timeout", name = "timeout")]
    prudent_command_timeout: Option<u64>,
}
