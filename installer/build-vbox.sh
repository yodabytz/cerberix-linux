#!/bin/bash
# ============================================================
# Cerberix Firewall — VirtualBox Image Builder
# ============================================================
# Converts the ISO to a bootable VDI for VirtualBox.
# Run: bash installer/build-vbox.sh
# Output: output/cerberix-0.3.0.vdi + .ova
# ============================================================

set -euo pipefail

VERSION="0.3.0"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ISO="${PROJECT_ROOT}/output/cerberix-${VERSION}.iso"
OUTPUT_DIR="${PROJECT_ROOT}/output"

if [ ! -f "${ISO}" ]; then
    echo "ISO not found. Building it first..."
    bash "${PROJECT_ROOT}/installer/build-iso.sh"
fi

echo "============================================"
echo "Cerberix Firewall VirtualBox Image Builder"
echo "============================================"

# Check for qemu-img on host
if ! command -v qemu-img &>/dev/null; then
    echo "Installing qemu-utils..."
    sudo apt-get install -y -qq qemu-utils 2>/dev/null || \
    sudo apk add --no-cache qemu-img 2>/dev/null || {
        echo "Please install qemu-utils: sudo apt install qemu-utils"
        exit 1
    }
fi

echo "[1/3] Creating 4GB raw disk image with ISO content..."

# Create a raw disk and embed the ISO as a bootable image
# For VirtualBox, the simplest approach is:
# 1. Create an empty VDI
# 2. User boots from ISO attached as CD, installs to disk
# OR: Create a pre-installed VDI using the host's loop devices

# Create empty VDI
qemu-img create -f vdi "${OUTPUT_DIR}/cerberix-${VERSION}.vdi" 8G

echo "[2/3] Creating VirtualBox machine config..."

# Create an OVA-compatible OVF descriptor
cat > "${OUTPUT_DIR}/cerberix-${VERSION}.ovf" << OVFEOF
<?xml version="1.0"?>
<Envelope ovf:version="2.0"
  xmlns="http://schemas.dmtf.org/ovf/envelope/2"
  xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/2"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
  xmlns:vbox="http://www.virtualbox.org/ovf/machine">
  <References>
    <File ovf:id="file1" ovf:href="cerberix-${VERSION}.vdi"/>
    <File ovf:id="file2" ovf:href="cerberix-${VERSION}.iso"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="8589934592" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <VirtualSystem ovf:id="CerberixLinux">
    <Info>Cerberix Firewall ${VERSION} (Hades) — AI-Powered Firewall Gateway</Info>
    <Name>Cerberix Firewall ${VERSION}</Name>
    <OperatingSystemSection ovf:id="102">
      <Info>Other Linux (64-bit)</Info>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>virtualbox-2.2</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:Caption>2 virtual CPUs</rasd:Caption>
        <rasd:Description>Number of virtual CPUs</rasd:Description>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Caption>2048 MB of memory</rasd:Caption>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>2048</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Caption>SATA Controller</rasd:Caption>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceType>20</rasd:ResourceType>
        <rasd:ResourceSubType>AHCI</rasd:ResourceSubType>
      </Item>
      <Item>
        <rasd:Caption>Disk Image</rasd:Caption>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceType>17</rasd:ResourceType>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:Parent>3</rasd:Parent>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
      </Item>
      <Item>
        <rasd:Caption>IDE Controller</rasd:Caption>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceType>5</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:Caption>CD-ROM</rasd:Caption>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:ResourceType>15</rasd:ResourceType>
        <rasd:HostResource>ovf:/file/file2</rasd:HostResource>
        <rasd:Parent>5</rasd:Parent>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
      </Item>
      <Item>
        <rasd:Caption>Ethernet adapter (WAN)</rasd:Caption>
        <rasd:InstanceID>7</rasd:InstanceID>
        <rasd:ResourceType>10</rasd:ResourceType>
        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>
        <rasd:Connection>Bridged</rasd:Connection>
      </Item>
      <Item>
        <rasd:Caption>Ethernet adapter (LAN)</rasd:Caption>
        <rasd:InstanceID>8</rasd:InstanceID>
        <rasd:ResourceType>10</rasd:ResourceType>
        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>
        <rasd:Connection>Internal</rasd:Connection>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVFEOF

echo "[3/3] Packaging OVA..."
cd "${OUTPUT_DIR}"
tar cf "cerberix-${VERSION}.ova" \
    "cerberix-${VERSION}.ovf" \
    "cerberix-${VERSION}.vdi" \
    "cerberix-${VERSION}.iso"

echo ""
echo "============================================"
echo "VirtualBox files ready!"
echo ""
ls -lh "${OUTPUT_DIR}/cerberix-${VERSION}".{vdi,ova,iso}
echo ""
echo "Option A — Import OVA (recommended):"
echo "  1. VirtualBox → File → Import Appliance"
echo "  2. Select: cerberix-${VERSION}.ova"
echo "  3. Boot — it will start from the ISO CD-ROM"
echo "  4. Login: root / cerberix"
echo "  5. Run: setup-disk /dev/sda (to install to disk)"
echo ""
echo "Option B — Manual setup:"
echo "  1. Create VM: Linux / Other Linux 64-bit"
echo "  2. RAM: 2048 MB, CPUs: 2"
echo "  3. Disk: Use cerberix-${VERSION}.vdi"
echo "  4. CD: Attach cerberix-${VERSION}.iso"
echo "  5. Network: Adapter 1 = Bridged (WAN)"
echo "              Adapter 2 = Internal (LAN)"
echo "  6. Boot from CD, install to disk"
echo "============================================"
