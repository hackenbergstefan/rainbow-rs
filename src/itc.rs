// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Inter-Thread-Communication

use std::sync::mpsc::{channel, Receiver, Sender};

use crate::Command;

pub struct BiChannel {
    sender: Sender<Command>,
    receiver: Receiver<Command>,
}

impl BiChannel {
    pub fn send(&self, data: Command) {
        self.sender.send(data).unwrap();
    }

    pub fn recv(&self) -> Command {
        self.receiver.recv().unwrap()
    }
}

pub struct RainbowITC {
    pub emu: BiChannel,
    pub victim: BiChannel,
}

pub fn create_itcs() -> (RainbowITC, RainbowITC) {
    let channel1 = channel();
    let channel2 = channel();
    let channel3 = channel();
    let channel4 = channel();
    (
        RainbowITC {
            emu: BiChannel {
                sender: channel1.0,
                receiver: channel2.1,
            },
            victim: BiChannel {
                sender: channel3.0,
                receiver: channel4.1,
            },
        },
        RainbowITC {
            emu: BiChannel {
                sender: channel2.0,
                receiver: channel1.1,
            },
            victim: BiChannel {
                sender: channel4.0,
                receiver: channel3.1,
            },
        },
    )
}
