use std::net::{TcpListener, TcpStream};
//use std::process::{Command};

use super::*;
use crate::*;

pub struct State {
    server_addr: String,
    server_sock: TcpListener,
    client_sock: Option<TcpStream>,
    client_args: ClientOptions,
    //command: Command,
}
impl State {
    pub fn new(s: &mut crate::State, core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<Self> {
        let server_addr = "127.0.0.1:0".to_string();
        let server_sock = TcpListener::bind(&server_addr)?;
        server_sock.set_nonblocking(true)?;

        let client_args = ClientOptions::default();


        Ok(Self {
            server_addr,
            server_sock,
            client_sock: None,
            client_args,
        })
    }

    pub fn spawn_client(&mut self) {
        if self.client_sock.is_some() {
            return;
        }
    }

    fn parse_config() {

    }
}

pub fn run_target(s: &mut crate::State) -> Result<TargetExitStatus> {
    Ok(TargetExitStatus::Normal(0))
}