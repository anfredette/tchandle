use anyhow::Result;
use aya::programs::tc::SchedClassifierLink;
use aya::programs::TcAttachType;

fn read_persisted_link_details() -> (String, TcAttachType, u16, u32) {
    ("eth0".to_string(), TcAttachType::Ingress, 50, 1)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Get the link parameters from some external source. Where and how the parameters are
    // persisted is up to your application.
    let (if_name, attach_type, priority, handle) = read_persisted_link_details();
    let _new_tc_link = SchedClassifierLink::attached(&if_name, attach_type, priority, handle)?;
    //new_tc_link.detach()?;

    Ok(())
}
