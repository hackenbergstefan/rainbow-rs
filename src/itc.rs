// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Inter-Thread-Communication

use crossbeam_channel::{Receiver, Sender};

/// Enum holding inter thread requests
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ITCRequest {
    /// Data to be passed to "victim".
    VictimData(Vec<u8>),
}

/// Enum holding inter thread responses
#[derive(Clone, Debug, PartialEq)]
pub enum ITCResponse {
    /// Answer to `GetTrace`.
    Trace(Vec<f32>),
}

#[derive(Clone)]
pub struct BiChannel<Req, Resp> {
    sender: Sender<Req>,
    receiver: Receiver<Resp>,
}

impl<Req, Resp> BiChannel<Req, Resp> {
    pub fn send(&self, data: Req) {
        self.sender.send(data).unwrap();
    }

    pub fn recv(&self) -> Result<Resp, crossbeam_channel::RecvError> {
        self.receiver.recv()
    }
}

pub fn create_inter_thread_channels() -> (
    BiChannel<ITCRequest, ITCResponse>,
    BiChannel<ITCResponse, ITCRequest>,
) {
    let (s1, r1) = crossbeam_channel::unbounded();
    let (s2, r2) = crossbeam_channel::unbounded();

    (
        BiChannel {
            sender: s1,
            receiver: r2,
        },
        BiChannel {
            sender: s2,
            receiver: r1,
        },
    )
}
