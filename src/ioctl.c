/***************************************************************************
 *                                                                         *
 *          ###########   ###########   ##########    ##########           *
 *         ############  ############  ############  ############          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ###########   ####  ######  ##   ##   ##  ##    ######          *
 *          ###########  ####  #       ##   ##   ##  ##    #    #          *
 *                   ##  ##    ######  ##   ##   ##  ##    #    #          *
 *                   ##  ##    #       ##   ##   ##  ##    #    #          *
 *         ############  ##### ######  ##   ##   ##  ##### ######          *
 *         ###########    ###########  ##   ##   ##   ##########           *
 *                                                                         *
 *            S E C U R E   M O B I L E   N E T W O R K I N G              *
 *                                                                         *
 * Copyright (c) 2019 Matthias Schulz                                      *
 *                                                                         *
 * Permission is hereby granted, free of charge, to any person obtaining a *
 * copy of this software and associated documentation files (the           *
 * "Software"), to deal in the Software without restriction, including     *
 * without limitation the rights to use, copy, modify, merge, publish,     *
 * distribute, sublicense, and/or sell copies of the Software, and to      *
 * permit persons to whom the Software is furnished to do so, subject to   *
 * the following conditions:                                               *
 *                                                                         *
 * 1. The above copyright notice and this permission notice shall be       *
 *    include in all copies or substantial portions of the Software.       *
 *                                                                         *
 * 2. Any use of the Software which results in an academic publication or  *
 *    other publication which includes a bibliography must include         *
 *    citations to the nexmon project a) and the paper cited under b):     *
 *                                                                         *
 *    a) "Matthias Schulz, Daniel Wegemer and Matthias Hollick. Nexmon:    *
 *        The C-based Firmware Patching Framework. https://nexmon.org"     *
 *                                                                         *
 *    b) "Francesco Gringoli, Matthias Schulz, Jakob Link, and Matthias    *
 *        Hollick. Free Your CSI: A Channel State Information Extraction   *
 *        Platform For Modern Wi-Fi Chipsets. Accepted to appear in        *
 *        Proceedings of the 13th Workshop on Wireless Network Testbeds,   *
 *        Experimental evaluation & CHaracterization (WiNTECH 2019),       *
 *        October 2019."                                                   *
 *                                                                         *
 * 3. The Software is not used by, in cooperation with, or on behalf of    *
 *    any armed forces, intelligence agencies, reconnaissance agencies,    *
 *    defense agencies, offense agencies or any supplier, contractor, or   *
 *    research associated.                                                 *
 *                                                                         *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS *
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF              *
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  *
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY    *
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,    *
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE       *
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                  *
 *                                                                         *
 **************************************************************************/

#pragma NEXMON targetregion "patch"

#include <firmware_version.h>   // definition of firmware version macros
#include <debug.h>              // contains macros to access the debug hardware
#include <wrapper.h>            // wrapper definitions for functions that already exist in the firmware
#include <local_wrapper.h>
#include <structs.h>            // structures that are used by the code in the firmware
#include <helper.h>             // useful helper functions
#include <patcher.h>            // macros used to craete patches such as BLPatch, BPatch, ...
#include <rates.h>              // rates used to build the ratespec for frame injection
#include <nexioctls.h>          // ioctls added in the nexmon patch
#include <version.h>            // version information
#include <argprintf.h>          // allows to execute argprintf to print into the arg buffer
#include <objmem.h>

#if NEXMON_CHIP == CHIP_VER_BCM4366c0
#define SHM_CSI_COLLECT         0xB80
#define NSSMASK                 0xB81
#define COREMASK                0xB82
#define APPLY_PKT_FILTER        0xB83
#define PKT_FILTER_BYTE         0xB84
#define N_CMP_SRC_MAC           0xB85
#define CMP_SRC_MAC_0_0         0xB86
#define CMP_SRC_MAC_0_1         0xB87
#define CMP_SRC_MAC_0_2         0xB88
#define CMP_SRC_MAC_1_0         0xB89
#define CMP_SRC_MAC_1_1         0xB8A
#define CMP_SRC_MAC_1_2         0xB8B
#define CMP_SRC_MAC_2_0         0xB8C
#define CMP_SRC_MAC_2_1         0xB8D
#define CMP_SRC_MAC_2_2         0xB8E
#define CMP_SRC_MAC_3_0         0xB8F
#define CMP_SRC_MAC_3_1         0xB90
#define CMP_SRC_MAC_3_2         0xB91
#define FORCEDEAF               0xB92
#define CLEANDEAF               0xB93
#define FIFODELAY               0xB94
#else
#define N_CMP_SRC_MAC           0x888
#define CMP_SRC_MAC_0_0         0x889
#define CMP_SRC_MAC_0_1         0x88A
#define CMP_SRC_MAC_0_2         0x88B
#define CMP_SRC_MAC_1_0         0x88C
#define CMP_SRC_MAC_1_1         0x88D
#define CMP_SRC_MAC_1_2         0x88E
#define CMP_SRC_MAC_2_0         0x88F
#define CMP_SRC_MAC_2_1         0x890
#define CMP_SRC_MAC_2_2         0x891
#define CMP_SRC_MAC_3_0         0x892
#define CMP_SRC_MAC_3_1         0x893
#define CMP_SRC_MAC_3_2         0x894
#define APPLY_PKT_FILTER        0x898
#define PKT_FILTER_BYTE         0x899
#define FIFODELAY               0x89e
#define SHM_CSI_COLLECT         0x8b0
#define	CLEANDEAF               0x8a3
#define	FORCEDEAF               0x8a4
#define NSSMASK                 0x8a6
#define COREMASK                0x8a7
#endif

void force_gainlevel(struct phy_info *pi, int16 int_val)
{
	/* disable clip2 */
    phy_utils_mod_phyreg(pi, 0x6d4, 0x1 << 13, 0x1 << 13);
    phy_reg_write(pi, 0x6db, 0xffff);

	switch (int_val) {
	case 0:
		printf("initgain -- adc never clips.\n");
        phy_reg_write(pi, 0x6da, 0xffff);   // clip1 Threshold
        phy_utils_mod_phyreg(pi, 0x6d4, 0x1 << 14, 0x1 << 14); // disable clip1 detect
		break;
	case 1:
		printf("clip hi -- adc always clips, nb never clips.\n");
        phy_utils_mod_phyreg(pi, 0x6ef, 0xff, 0xff);
		break;
	case 2:
		printf("clip md -- adc/nb always clips, w1 never clips.\n");
        phy_utils_mod_phyreg(pi, 0x6ef, 0xff, 0x0);         // FastAgcClipCntTh Nb
        phy_utils_mod_phyreg(pi, 0x6ef, 0xff << 8, 0xff);   // FastAgcClipCntTh W1
		break;
	case 3:
		printf("clip lo -- adc/nb/w1 always clips.\n");
		phy_utils_mod_phyreg(pi, 0x6ef, 0xff, 0x0);
        phy_utils_mod_phyreg(pi, 0x6ef, 0xff << 8, 0x0);
		break;
	case 4:
		printf("adc clip.\n");
        phy_reg_write(pi, 0x6de, 0x0);
        phy_reg_write(pi, 0x6df, 0x8);
        phy_utils_mod_phyreg(pi, 0x6ef, 0xff, 0xff);
		break;
	case 5:
		printf("nb clip.\n");
        phy_reg_write(pi, 0x6e0, 0xfffe);
        phy_reg_write(pi, 0x6e1, 0x554);
        phy_utils_mod_phyreg(pi, 0x6ef, 0xff << 8, 0xff);
		break;
	case 6:
		printf("w1 clip.\n");
        phy_reg_write(pi, 0x6e2, 0xfffe);
        phy_reg_write(pi, 0x6e3, 0x554);
        phy_utils_mod_phyreg(pi, 0x6ee, 0x3, 0x0);
		break;
	}
}

int 
wlc_ioctl_hook(struct wlc_info *wlc, int cmd, char *arg, int len, void *wlc_if)
{
    int ret = IOCTL_ERROR;
    argprintf_init(arg, len);

    struct phy_info *pi = wlc->hw->band->pi;

    switch(cmd) {
        case 500:   // set csi_collect
        {
            struct params {
                uint16 chanspec;            // chanspec to tune to
                uint8  csi_collect;         // trigger csi collect (1: on, 0: off)
                uint8  core_nss_mask;       // coremask and spatialstream mask
                uint8  use_pkt_filter;      // trigger first packet byte filter (1: on, 0: off)
                uint8  first_pkt_byte;      // first packet byte to filter for
                uint16 n_mac_addr;          // number of mac addresses to filter for (0: off, 1-4: on,use src_mac_0-3)
                uint16 cmp_src_mac_0_0;     // filter src mac 0
                uint16 cmp_src_mac_0_1;
                uint16 cmp_src_mac_0_2;
                uint16 cmp_src_mac_1_0;     // filter src mac 1
                uint16 cmp_src_mac_1_1;
                uint16 cmp_src_mac_1_2;
                uint16 cmp_src_mac_2_0;     // filter src mac 2
                uint16 cmp_src_mac_2_1;
                uint16 cmp_src_mac_2_2;
                uint16 cmp_src_mac_3_0;     // filter src mac 3
                uint16 cmp_src_mac_3_1;
                uint16 cmp_src_mac_3_2;
                uint16 delay;               // delay between extractions in us
            };
            struct params *params = (struct params *) arg;
            // deactivate scanning
            set_scansuppress(wlc, 1);
            // deactivate minimum power consumption
            set_mpc(wlc, 0);
            // set the channel
            set_chanspec(wlc, params->chanspec);
            // write shared memory
            if (wlc->hw->up && len > 1) {
                wlc_bmac_write_shm(wlc->hw, SHM_CSI_COLLECT * 2, params->csi_collect);
                wlc_bmac_write_shm(wlc->hw, NSSMASK * 2, ((params->core_nss_mask)&0xf0)>>4);
                wlc_bmac_write_shm(wlc->hw, COREMASK * 2, (params->core_nss_mask)&0x0f);
                wlc_bmac_write_shm(wlc->hw, N_CMP_SRC_MAC * 2, params->n_mac_addr);
                wlc_bmac_write_shm(wlc->hw, APPLY_PKT_FILTER * 2, params->use_pkt_filter);
                wlc_bmac_write_shm(wlc->hw, PKT_FILTER_BYTE * 2, params->first_pkt_byte);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_0_0 * 2, params->cmp_src_mac_0_0);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_0_1 * 2, params->cmp_src_mac_0_1);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_0_2 * 2, params->cmp_src_mac_0_2);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_1_0 * 2, params->cmp_src_mac_1_0);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_1_1 * 2, params->cmp_src_mac_1_1);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_1_2 * 2, params->cmp_src_mac_1_2);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_2_0 * 2, params->cmp_src_mac_2_0);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_2_1 * 2, params->cmp_src_mac_2_1);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_2_2 * 2, params->cmp_src_mac_2_2);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_3_0 * 2, params->cmp_src_mac_3_0);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_3_1 * 2, params->cmp_src_mac_3_1);
                wlc_bmac_write_shm(wlc->hw, CMP_SRC_MAC_3_2 * 2, params->cmp_src_mac_3_2);
                wlc_bmac_write_shm(wlc->hw, FIFODELAY * 2, params->delay);
                ret = IOCTL_SUCCESS;
            }
            break;
        }
        case 501:   // get csi collect
        {
            if (wlc->hw->up && len > 1) {
                *(uint16 *) arg = wlc_bmac_read_shm(wlc->hw, SHM_CSI_COLLECT * 2);
                ret = IOCTL_SUCCESS;
            }
            break;
        }
        case 502:	// force deaf mode
        {
                if (wlc->hw->up && len > 1) {
            wlc_bmac_write_shm(wlc->hw, FORCEDEAF * 2, 1);
            ret = IOCTL_SUCCESS;
            }
            break;
        }
        case 503:	// clean deaf mode
        {
                if (wlc->hw->up && len > 1) {
            wlc_bmac_write_shm(wlc->hw, CLEANDEAF * 2, 1);
            ret = IOCTL_SUCCESS;
            }
                break;
        }
        case NEX_READ_OBJMEM:
        {
            set_mpc(wlc, 0);
            if (wlc->hw->up && len >= 4) {
                int addr = ((int *) arg)[0];
                int i = 0;
                for (i = 0; i < len / 4; i++) {
                    wlc_bmac_read_objmem32_objaddr(wlc->hw, addr + i, &((unsigned int *) arg)[i]);
                }
                ret = IOCTL_SUCCESS;
            }
            break;
        }
        case 540: // setup
        {
            // deactivate minimum power consumption
            set_mpc(wlc, 0);
            ret = IOCTL_SUCCESS;
            break;
        }
        case 541: // disable agc (doesn't work)
        {
            wlc_phyreg_enter(pi);
            wlc_phy_stay_in_carriersearch_acphy(pi, 1);

            // dot11acConfig
            phy_reg_write(pi, 0x1f5, 0);

            // ACPHY_HPFBWovrdigictrl_HTAGC_HPFBW
            phy_utils_mod_phyreg(pi, 0x1f6, 0x1, 0);
            phy_utils_mod_phyreg(pi, 0x1f6, 0x2, 0);
            // ACPHY_HPFBWovrdigictrl_VHTAGC_HPFBW
            phy_utils_mod_phyreg(pi, 0x1f6, 0x10, 0);
            phy_utils_mod_phyreg(pi, 0x1f6, 0x20, 0);

            // ACPHY_RadarBlankCtrl_radarHtAgcBlankEn
            phy_utils_mod_phyreg(pi, 0x250, 0x2000, 0);

            // singleShotAgcCtrl
            phy_utils_mod_phyreg(pi, 0x29c, 0x8000, 1);

            wlc_phy_stay_in_carriersearch_acphy(pi, 0);
            wlc_phyreg_exit(pi);

            ret = IOCTL_SUCCESS;
            break;
        }
        case 545: // force gain level
        {
            wlc_phyreg_enter(pi);
            wlc_phy_stay_in_carriersearch_acphy(pi, 1);

            force_gainlevel(pi, ((int *) arg)[0]);

            wlc_phy_stay_in_carriersearch_acphy(pi, 0);
            wlc_phyreg_exit(pi);

            ret = IOCTL_SUCCESS;
            break;
        }
        case 546: // set max analog gain
        {
            wlc_phyreg_enter(pi);
            wlc_phy_stay_in_carriersearch_acphy(pi, 1);

            int val = 0x9f + ((((int *) arg)[0]) * 0x100);
            phy_reg_write(pi, 0x6e8, val);

            wlc_phy_stay_in_carriersearch_acphy(pi, 0);
            wlc_phyreg_exit(pi);

            ret = IOCTL_SUCCESS;
            break;
        }
        case 548: // programm gain limit tables
        {
            // uint8 tia[]     = {10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43};
	        // uint8 tiabits[] = { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11};

            // int8 dvga1_gain[] = {-12, -6, 0};    // bq1
	        // uint8 dvga1_gainbits[] = {0, 1, 2};

            // int8 dvga_gain[] = {0, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42};
	        // uint8 dvga_gainbits[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};

            struct phy_info_acphy *pi_ac = pi->pi_ac;       

            wlc_phyreg_enter(pi);
            wlc_phy_stay_in_carriersearch_acphy(pi, 1);

            uint8 used = 0;
            uint8 unused = 127;

            uint8 lna1_gaintbl[] = {0xa, 0xa, 0xa, 0xa, 0xa, 0xa};
            uint8 lna1_gainbitstbl[] = {2, 2, 2, 2, 2, 2};

            uint8 tia_gaintbl[] = {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10};
            uint8 tia_gainbitstbl[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            uint8 bq1_gaintbl[] = {0, 0, 0};
            uint8 bq1_gainbitstbl[] = {0, 0, 0};

            int8 dvga_gain[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	        uint8 dvga_gainbits[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            wlc_phy_table_write_acphy_rp(pi, 0xb, 1, 8 + 0, 8, &unused);
            wlc_phy_table_write_acphy_rp(pi, 0xb, 1, 8 + 1, 8, &unused);
            wlc_phy_table_write_acphy_rp(pi, 0xb, 1, 8 + 2, 8, &used);
            wlc_phy_table_write_acphy_rp(pi, 0xb, 1, 8 + 3, 8, &unused);
            wlc_phy_table_write_acphy_rp(pi, 0xb, 1, 8 + 4, 8, &unused);
            wlc_phy_table_write_acphy_rp(pi, 0xb, 1, 8 + 5, 8, &unused);

            wlc_phy_table_write_acphy_rp(pi, 0x44, 6, 8, 8, lna1_gaintbl);
            wlc_phy_table_write_acphy_rp(pi, 0x45, 6, 8, 8, lna1_gainbitstbl);

            wlc_phy_table_write_acphy_rp(pi, 0x44, 0xc, 32, 8, tia_gaintbl);
            wlc_phy_table_write_acphy_rp(pi, 0x45, 0xc, 32, 8, tia_gainbitstbl);

            wlc_phy_table_write_acphy_rp(pi, 0x44, 3, 0x70, 8, bq1_gaintbl);
            wlc_phy_table_write_acphy_rp(pi, 0x45, 3, 0x70, 8, bq1_gainbitstbl);

            memcpy(pi_ac->rxgainctrl_params.gaintbl[6], dvga_gain, sizeof(pi_ac->rxgainctrl_params.gaintbl[0][0]) * 12);
            memcpy(pi_ac->rxgainctrl_params.gainbitstbl[6], dvga_gainbits, sizeof(pi_ac->rxgainctrl_params.gaintbl[0][0]) * 12);

            wlc_phy_stay_in_carriersearch_acphy(pi, 0);
            wlc_phyreg_exit(pi);

            ret = IOCTL_SUCCESS;
            break;
        }
        case 610:
        {
            // writes the string from arg to the console
            if (len > 0) {
                arg[len-1] = 0;
                printf("ioctl: %s\n", arg);
                ret = IOCTL_SUCCESS; 
            }
            break;
        }
        case 611:
        {
            // reads the value from arg[0] to arg[0]
            if(wlc->hw->up) {
                wlc_phyreg_enter(pi);
                wlc_phy_stay_in_carriersearch_acphy(pi, 1);

                *(int *) arg =  phy_utils_read_phyreg(pi, ((int *) arg)[0]);

                wlc_phy_stay_in_carriersearch_acphy(pi, 0);
                wlc_phyreg_exit(pi);
                
            }
            ret = IOCTL_SUCCESS;
            break;
        }
        case 612:
        {
            // writes the value arg[1] to physical layer register arg[0]
            if(wlc->hw->up && len >= 8) {
                wlc_phyreg_enter(wlc->band->pi);
                phy_reg_write(wlc->band->pi, ((int *) arg)[1], ((int *) arg)[0]);
                wlc_phyreg_exit(wlc->band->pi);
                ret = IOCTL_SUCCESS;
            }
            break;
        }
        case 613:
        {
            // reads the value from arg[0] to arg[0]
            
            wlc_phyreg_enter(pi);
            wlc_phy_stay_in_carriersearch_acphy(pi, 1);

            *(int *) arg =  phy_utils_read_phyreg(pi, ((int *) arg)[0]);

            wlc_phy_stay_in_carriersearch_acphy(pi, 0);
            wlc_phyreg_exit(pi);
                
            ret = IOCTL_SUCCESS;
            break;
        }

        default:
            ret = wlc_ioctl(wlc, cmd, arg, len, wlc_if);
    }

    return ret;
}

__attribute__((at(0x1F3488, "", CHIP_VER_BCM4339, FW_VER_6_37_32_RC23_34_43_r639704)))
__attribute__((at(0x20CD80, "", CHIP_VER_BCM43455c0, FW_VER_7_45_189)))
__attribute__((at(0x1F3230, "", CHIP_VER_BCM4358, FW_VER_7_112_300_14)))
__attribute__((at(0x2F0CF8, "", CHIP_VER_BCM4366c0, FW_VER_10_10_122_20)))
GenericPatch4(wlc_ioctl_hook, wlc_ioctl_hook + 1);
