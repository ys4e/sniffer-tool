use std::fmt::{Display, Formatter};
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use pcap::Device;
use anyhow::Result;

/// Prompts the user to select a network device.
pub fn select() -> Result<String> {
    // Get all devices for packet capturing.
    let device_list = Device::list()?;
    let device_names = CaptureDevice::into(&device_list);

    let device = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a network device to capture from")
        .default(0)
        .items(&device_names)
        .interact()?;
    Ok(device_list[device].name.clone())
}

pub struct CaptureDevice(Device);

impl CaptureDevice {
    /// Converts a list of devices into a list of capture devices.
    pub fn into(devices: &Vec<Device>) -> Vec<CaptureDevice> {
        devices
            .into_iter()
            .map(|d| CaptureDevice(d.clone()))
            .collect()
    }
}

impl Display for CaptureDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let description = match self.0.desc {
            Some(ref desc) => desc,
            None => "No description"
        };

        write!(f, "{}", description)
    }
}