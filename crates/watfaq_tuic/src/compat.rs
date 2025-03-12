use std::{
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::anyhow;
use futures::{Sink, SinkExt, Stream};
use watfaq_types::UdpPacket;

use super::TuicUdpOutbound;
