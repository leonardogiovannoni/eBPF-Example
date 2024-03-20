use anyhow::anyhow;
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use network_types::ip::Ipv4Hdr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}
const BPF_BYTES: &'static [u8] = include_bytes_aligned!(env!("CONFIG_DAT_PATH"));


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut  bpf = Ebpf::load(BPF_BYTES)?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp =
        bpf.program_mut("get_ip_source").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let tmp = bpf.take_map("EVENTS").ok_or(anyhow!("NOPE"))?;
    let mut events = AsyncPerfEventArray::try_from(tmp)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(10240); num_cpus];
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Ipv4Hdr;
                    let data = unsafe { ptr.read_unaligned() };
                    println!("{:?}", data);
                }
            }
        });
    }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
