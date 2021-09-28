import numpy as np
import struct
import os
import pandas as pd


class CSIDataPcapReader:
    CSI_TOOL_VERSION_ORIGINAL = 0
    CSI_TOOL_VERSION_INCLUDE_RSSI = 1
    CSI_TOOL_VERSION_TEST_PHYSTATUS = 2
    CSI_TOOL_VERSION_GAIN_RECOVERY = 3
    CSI_TOOL_VERSION_GAIN_RECOVERY_V2 = 4

    def __init__(self, pcap_file, bandwidth, csi_tool_ver=CSI_TOOL_VERSION_INCLUDE_RSSI):
        self.pcap = CSIDataPcap(pcap_file, bandwidth, csi_tool_ver)

    def get_data_frame(self):
        return self.pcap.read()

    def write_to_csv(self, filename):
        df = self.pcap.read()
        df.to_csv(filename, index=False)


class CSIDataPcapFrame:
    FRAME_HEADER_DTYPE = np.dtype([
        ("ts_sec", np.uint32),
        ("ts_usec", np.uint32),
        ("incl_len", np.uint32),
        ("orig_len", np.uint32),
    ])

    UDP_HEADER_LENGTH = 42

    PAYLOAD_HEADER_LENGTH_BY_CSI_TOOL_VER = {
        CSIDataPcapReader.CSI_TOOL_VERSION_ORIGINAL: 22,
        CSIDataPcapReader.CSI_TOOL_VERSION_INCLUDE_RSSI: 22,
        CSIDataPcapReader.CSI_TOOL_VERSION_TEST_PHYSTATUS: 22,
        CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY: 30,
        CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY_V2: 70
    }

    def __init__(self, data, offset, csi_tool_ver):
        self.data = data
        self.offset = offset
        self.csi_tool_ver = csi_tool_ver

        self.header = self.read_header()
        self.payload_header = self.read_payload_header(data[self.offset + self.UDP_HEADER_LENGTH:
                                                            self.offset + self.UDP_HEADER_LENGTH
                                                            + self.PAYLOAD_HEADER_LENGTH_BY_CSI_TOOL_VER[
                                                                self.csi_tool_ver]])
        self.payload = self.read_payload(data)

    def read_header(self):
        header = np.frombuffer(self.data[self.offset:self.offset + self.FRAME_HEADER_DTYPE.itemsize],
                               dtype=self.FRAME_HEADER_DTYPE)
        self.offset += self.FRAME_HEADER_DTYPE.itemsize
        return header

    def read_payload_header(self, payload_data):
        header = dict()

        if self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_INCLUDE_RSSI:
            header["rssi"] = struct.unpack("b", payload_data[2:3])[0]
        elif self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY:
            header["rssi"] = struct.unpack("b", payload_data[2:3])[0]
            header["elna"] = struct.unpack("b", payload_data[18:19])[0]
            header["lna1"] = struct.unpack("b", payload_data[19:20])[0]
            header["lna2"] = struct.unpack("b", payload_data[20:21])[0]
            header["mix"] = struct.unpack("b", payload_data[21:22])[0]
            header["lpf0"] = struct.unpack("b", payload_data[22:23])[0]
            header["lpf1"] = struct.unpack("b", payload_data[23:24])[0]
            header["dvga"] = struct.unpack("b", payload_data[24:25])[0]
            header["trLoss"] = struct.unpack("b", payload_data[25:26])[0]
            header["agcGain"] = struct.unpack("h", payload_data[26:28])[0]
        elif self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY_V2:
            header["rssi"] = struct.unpack("b", payload_data[2:3])[0]
            column_name_extensions = CSIDataPcap.GAIN_RECOVERY_V2_COLUMN_NAME_EXT
            for i in range(0, 6):
                header["elna" + column_name_extensions[i]] = struct.unpack("b", payload_data[18 + i:19 + i])[0]
                header["lna1" + column_name_extensions[i]] = struct.unpack("b", payload_data[18 + i + 6:19 + i + 6])[0]
                header["lna2" + column_name_extensions[i]] = struct.unpack(
                    "b", payload_data[18 + i + 12:19 + i + 12])[0]
                header["mix" + column_name_extensions[i]] = struct.unpack(
                    "b", payload_data[18 + i + 18:19 + i + 18])[0]
                header["lpf0" + column_name_extensions[i]] = struct.unpack(
                    "b", payload_data[18 + i + 24:19 + i + 24])[0]
                header["lpf1" + column_name_extensions[i]] = struct.unpack(
                    "b", payload_data[18 + i + 30:19 + i + 30])[0]
                header["dvga" + column_name_extensions[i]] = struct.unpack(
                    "b", payload_data[18 + i + 36:19 + i + 36])[0]
                header["trLoss" + column_name_extensions[i]] = struct.unpack(
                    "b", payload_data[18 + i + 42:19 + i + 42])[0]

        header["agcGain"] = struct.unpack("h", payload_data[66:68])[0]

        return header

    def read_payload(self, data):
        incl_len = self.header["incl_len"][0]
        if incl_len <= 0:
            return False

        if (incl_len % 4) == 0:
            ints_size = int(incl_len / 4)
            payload = np.array(struct.unpack(ints_size * "I", data[self.offset:self.offset + incl_len]),
                               dtype=np.uint32)
        else:
            ints_size = incl_len
            payload = np.array(struct.unpack(ints_size * "B", data[self.offset:self.offset + incl_len]), dtype=np.uint8)

        self.offset += incl_len

        return payload


class CSIDataPcap:
    HEADER_OFFSET_BY_CSI_TOOL_VER = {
        CSIDataPcapReader.CSI_TOOL_VERSION_ORIGINAL: 16,
        CSIDataPcapReader.CSI_TOOL_VERSION_INCLUDE_RSSI: 16,
        CSIDataPcapReader.CSI_TOOL_VERSION_TEST_PHYSTATUS: 17,
        CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY: 19,
        CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY_V2: 29
    }

    PCAP_HEADER_DTYPE = np.dtype([
        ("magic_number", np.uint32),
        ("version_major", np.uint16),
        ("version_minor", np.uint16),
        ("thiszone", np.int32),
        ("sigfigs", np.uint32),
        ("snaplen", np.uint32),
        ("network", np.uint32)
    ])

    SUBCARRIER_COUNT_BY_BW = {
        20: 64,
        40: 128,
        80: 256
    }

    PRXS2_ACPHY_RXPWR_ANT0_MASK = 0xFF00
    PRXS2_ACPHY_RXPWR_ANT0_SHIFT = 8
    PRXS2_LNAGN_MASK = 0xc000
    PRXS2_LNAGN_SHIFT = 14
    PRXS2_PGAGN_MASK = 0x3C00
    PRXS2_PGAGN_SHIFT = 10
    PRXS2_FOFF_MASK = 0x03FF

    GAIN_RECOVERY_V2_COLUMN_NAME_EXT = ["_1", "_2", "_3", "_4", "_9", "_10"]

    def __init__(self, filename, bandwidth, csi_tool_ver=CSIDataPcapReader.CSI_TOOL_VERSION_ORIGINAL):
        self.bandwidth = bandwidth
        self.csi_tool_ver = csi_tool_ver
        self.nfft = int(bandwidth * 3.2)
        self.data = open(filename, "rb").read()
        self.header = np.frombuffer(self.data[:self.PCAP_HEADER_DTYPE.itemsize], dtype=self.PCAP_HEADER_DTYPE)
        self.frames = []
        self.sc_count = self.SUBCARRIER_COUNT_BY_BW[bandwidth]
        self.df = pd.DataFrame(columns=np.arange(self.sc_count))

    def read(self):
        if self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_TEST_PHYSTATUS:
            rxpower = list()
            lnagn = list()
            pgagn = list()
            foff = list()

        offset = self.PCAP_HEADER_DTYPE.itemsize
        while offset < len(self.data):
            nextFrame = CSIDataPcapFrame(self.data, offset, self.csi_tool_ver)
            offset = nextFrame.offset

            header_offset = self.HEADER_OFFSET_BY_CSI_TOOL_VER[self.csi_tool_ver]
            if nextFrame.header["orig_len"][0] - (header_offset - 1) * 4 != self.nfft * 4:
                print("Skipped frame with incorrect size.")
            else:
                self.frames.append(nextFrame)

            csi_data = nextFrame.payload[-self.sc_count:]
            csi_data.dtype = np.int16
            csi = np.zeros((self.sc_count,), dtype=np.complex)
            csi_data = csi_data.reshape(-1, 2)
            i = 0
            for x in csi_data:
                csi[i] = np.complex(x[0], x[1])
                i += 1

            if self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_TEST_PHYSTATUS:
                phy_rx_status_2_data = csi_data[29][0]
                rxpower.append((phy_rx_status_2_data & self.PRXS2_ACPHY_RXPWR_ANT0_MASK)
                               >> self.PRXS2_ACPHY_RXPWR_ANT0_SHIFT)
                lnagn.append((phy_rx_status_2_data & self.PRXS2_LNAGN_MASK) >> self.PRXS2_LNAGN_SHIFT)
                pgagn.append((phy_rx_status_2_data & self.PRXS2_PGAGN_MASK) >> self.PRXS2_PGAGN_SHIFT)
                foff.append(phy_rx_status_2_data & self.PRXS2_FOFF_MASK)

            self.df = self.df.append(pd.Series(csi), ignore_index=True)

        if self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_INCLUDE_RSSI \
                or self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_TEST_PHYSTATUS \
                or self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY \
                or self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY_V2:
            rssi = [f.payload_header["rssi"] for f in self.frames]
            self.df["RSSI"] = rssi
        if self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_TEST_PHYSTATUS:
            self.df["rxpower"] = rxpower
            self.df["lnagn"] = lnagn
            self.df["pgagn"] = pgagn
            self.df["foff"] = foff

        if self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY:
            elna = [f.payload_header["elna"] for f in self.frames]
            lna1 = [f.payload_header["lna1"] for f in self.frames]
            lna2 = [f.payload_header["lna2"] for f in self.frames]
            mix = [f.payload_header["mix"] for f in self.frames]
            lpf0 = [f.payload_header["lpf0"] for f in self.frames]
            lpf1 = [f.payload_header["lpf1"] for f in self.frames]
            dvga = [f.payload_header["dvga"] for f in self.frames]
            tr_loss = [f.payload_header["trLoss"] for f in self.frames]
            agc_gain = [f.payload_header["agcGain"] for f in self.frames]

            self.df["elna"] = elna
            self.df["lna1"] = lna1
            self.df["lna2"] = lna2
            self.df["mix"] = mix
            self.df["lpf0"] = lpf0
            self.df["lpf1"] = lpf1
            self.df["dvga"] = dvga
            self.df["trLoss"] = tr_loss
            self.df["agcGain"] = agc_gain

        if self.csi_tool_ver == CSIDataPcapReader.CSI_TOOL_VERSION_GAIN_RECOVERY_V2:
            for name_ext in self.GAIN_RECOVERY_V2_COLUMN_NAME_EXT:
                elna = [f.payload_header["elna" + name_ext] for f in self.frames]
                lna1 = [f.payload_header["lna1" + name_ext] for f in self.frames]
                lna2 = [f.payload_header["lna2" + name_ext] for f in self.frames]
                mix = [f.payload_header["mix" + name_ext] for f in self.frames]
                lpf0 = [f.payload_header["lpf0" + name_ext] for f in self.frames]
                lpf1 = [f.payload_header["lpf1" + name_ext] for f in self.frames]
                dvga = [f.payload_header["dvga" + name_ext] for f in self.frames]
                tr_loss = [f.payload_header["trLoss" + name_ext] for f in self.frames]

                self.df["elna" + name_ext] = elna
                self.df["lna1" + name_ext] = lna1
                self.df["lna2" + name_ext] = lna2
                self.df["mix" + name_ext] = mix
                self.df["lpf0" + name_ext] = lpf0
                self.df["lpf1" + name_ext] = lpf1
                self.df["dvga" + name_ext] = dvga
                self.df["trLoss" + name_ext] = tr_loss

            agc_gain = [f.payload_header["agcGain"] for f in self.frames]
            self.df["agcGain"] = agc_gain

        return self.df
