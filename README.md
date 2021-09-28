Fork from [Nexemon CSI Extractor](https://github.com/seemoo-lab/nexmon_csi) but also extracts gain values for the different gain stages. It is also possible to limit or fix the gain stages to certain gain levels (currently only works for lna1, lna2 and tia(mixer) ).

To see how it works, refer to comments in code. Extraction is implemented in src/csi_extractor.c (especially in function get_rx_gains). src/ioctl.c contains ioctls to set the gain levels. 

There are different "gain_types". In my experiments gain values only changed for gain_type = 10. This patch extracts gain values for gain_types (1,2,3,4,9 and 10).

The folde rpcap_reading contains a python script to read the captured pcap files. Usage: 

```python
import read_pcap as rp

reader = rp.CSIDataPcapReader(SOURCE_FILE, BANDWIDTH, rp.CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY_V2)

reader.write_to_csv(OUTPUT_FILE)
```
