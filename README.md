Fork from [Nexemon CSI Extractor](https://github.com/seemoo-lab/nexmon_csi) but also extracts gain values for the different gain stages. It is also possible to limit or fix the gain stages to certain gain levels (currently only works for lna1, lna2 and tia(mixer) ).

To see how it works, refer to comments in code. Extraction is implemented in src/csi_extractor.c. src/ioctl.c contains ioctls to set the gain levels. 
