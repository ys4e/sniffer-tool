use std::fmt::{Display, Formatter};
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use pcap::Device;
use anyhow::{bail, Result};

/// Prompts the user to select a network device.
///
/// When `wanted` is given, the device is picked without prompting:
/// by its index in the list, its exact name, or a part of its description.
pub fn select(wanted: Option<&str>) -> Result<String> {
    // Get all devices for packet capturing.
    let device_list = Device::list()?;
    let device_names = CaptureDevice::into(&device_list);

    if let Some(wanted) = wanted {
        let lowered = wanted.to_lowercase();
        let found = wanted.parse::<usize>().ok()
            .and_then(|index| device_list.get(index))
            .or_else(|| device_list.iter().find(|d| d.name == wanted))
            .or_else(|| device_list.iter().find(|d| d.desc.as_ref()
                .is_some_and(|desc| desc.to_lowercase().contains(&lowered))));

        let Some(device) = found else {
            for (index, device) in device_names.iter().enumerate() {
                info!("{index}: {device} ({})", device.0.name);
            }
            bail!("No network device matches '{wanted}'");
        };

        info!("Capturing from {}.", CaptureDevice(device.clone()));
        return Ok(device.name.clone());
    }

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