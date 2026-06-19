/* ==========================================================================
   Smart Camera Gateway — Application Logic
   ========================================================================== */

const API_BASE = "http://127.0.0.1:5000/api";

// Session state
let currentEmail = "";
let currentRole = "";
let deviceInterval = null;
let systemStartTime = Date.now();

// ==========================================================================
// Initialization
// ==========================================================================
document.addEventListener("DOMContentLoaded", () => {
    bindAuthEvents();
    bindDashboardEvents();
    bindTotpEvents();
    startUptimeClock();
});

// ==========================================================================
// Toast Notification System
// ==========================================================================
function showToast(title, message, type = "info", duration = 4000) {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;

    const icons = {
        success: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
        error:   `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
        warning: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        info:    `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`
    };

    const titles = {
        success: title || "操作成功",
        error:   title || "操作失败",
        warning: title || "请注意",
        info:    title || "提示"
    };

    toast.innerHTML = `
        <div class="toast-icon">${icons[type]}</div>
        <div class="toast-body">
            <div class="toast-title">${titles[type]}</div>
            <div class="toast-msg">${message}</div>
        </div>
    `;

    container.appendChild(toast);

    // Auto dismiss
    const timer = setTimeout(() => {
        toast.classList.add("removing");
        setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 200);
    }, duration);

    // Click to dismiss early
    toast.addEventListener("click", () => {
        clearTimeout(timer);
        toast.classList.add("removing");
        setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 200);
    });
}

// ==========================================================================
// Auth Events
// ==========================================================================
function bindAuthEvents() {
    // Tab switching
    document.getElementById("tabLoginBtn").addEventListener("click", () => switchAuthTab(0));
    document.getElementById("tabRegBtn").addEventListener("click", () => switchAuthTab(1));

    // Core actions
    document.getElementById("btnLogin").addEventListener("click", doLogin);
    document.getElementById("btnRegister").addEventListener("click", doRegister);
    document.getElementById("btnVerifyTotp").addEventListener("click", verifyTotp);
    document.getElementById("btnBackToLogin").addEventListener("click", backToLogin);

    // Enter key support
    document.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const authCard = document.getElementById("authView");
            const totpCard = document.getElementById("totpView");

            if (totpCard.style.display !== "none") {
                verifyTotp();
            } else if (authCard.style.display !== "none") {
                const loginVisible = document.getElementById("loginBox").style.display !== "none";
                if (loginVisible) doLogin(); else doRegister();
            }
        }
    });
}

// ==========================================================================
// Dashboard Events
// ==========================================================================
function bindDashboardEvents() {
    document.getElementById("btnRegisterDevice").addEventListener("click", registerDevice);
    document.getElementById("btnOpenDeviceModal").addEventListener("click", openDeviceModal);
    document.getElementById("btnCloseModal").addEventListener("click", closeDeviceModal);
    document.getElementById("btnCancelDevice").addEventListener("click", closeDeviceModal);
    document.getElementById("btnLogout").addEventListener("click", logout);

    // Modal overlay click to close
    document.getElementById("deviceModal").addEventListener("click", (e) => {
        if (e.target === e.currentTarget) closeDeviceModal();
    });

    // Escape key to close modal
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeDeviceModal();
    });

    // Mobile menu
    document.getElementById("menuToggle").addEventListener("click", toggleSidebar);
    document.getElementById("sidebarOverlay").addEventListener("click", toggleSidebar);

    // Nav items — page switching
    document.querySelectorAll(".nav-item[data-nav]").forEach(item => {
        item.addEventListener("click", function () {
            document.querySelectorAll(".nav-item[data-nav]").forEach(i => i.classList.remove("active"));
            this.classList.add("active");
            switchPage(this.dataset.nav);
        });
    });

    // Playback device selector
    document.getElementById("playbackDeviceSelect").addEventListener("change", function () {
        onPlaybackDeviceChange(this.value);
    });
}

// ==========================================================================
// TOTP Digit Input Handlers
// ==========================================================================
function bindTotpEvents() {
    const digits = document.querySelectorAll(".totp-digit");

    digits.forEach((input, index) => {
        // Auto-focus next digit
        input.addEventListener("input", (e) => {
            const val = e.target.value;
            if (val.length === 1) {
                input.classList.add("filled");
                if (index < digits.length - 1) {
                    digits[index + 1].focus();
                }
            } else if (val.length === 0) {
                input.classList.remove("filled");
            }
        });

        // Handle backspace
        input.addEventListener("keydown", (e) => {
            if (e.key === "Backspace" && input.value === "" && index > 0) {
                digits[index - 1].focus();
                digits[index - 1].classList.remove("filled");
            }
            // Arrow keys
            if (e.key === "ArrowLeft" && index > 0) {
                digits[index - 1].focus();
                digits[index - 1].select();
            }
            if (e.key === "ArrowRight" && index < digits.length - 1) {
                digits[index + 1].focus();
                digits[index + 1].select();
            }
        });

        // Handle paste
        input.addEventListener("paste", (e) => {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData("text");
            const numbers = paste.replace(/\D/g, "").slice(0, 6);
            numbers.split("").forEach((char, i) => {
                if (digits[i]) {
                    digits[i].value = char;
                    digits[i].classList.add("filled");
                }
            });
            const focusIndex = Math.min(numbers.length, digits.length - 1);
            digits[focusIndex].focus();
        });
    });
}

// ==========================================================================
// Auth Tab Switching
// ==========================================================================
function switchAuthTab(index) {
    document.getElementById("tabLoginBtn").classList.toggle("active", index === 0);
    document.getElementById("tabRegBtn").classList.toggle("active", index === 1);
    document.getElementById("loginBox").classList.toggle("visible", index === 0);
    document.getElementById("regBox").classList.toggle("visible", index === 1);
}

// ==========================================================================
// Auth: Register
// ==========================================================================
async function doRegister() {
    const btn = document.getElementById("btnRegister");
    const text = document.getElementById("btnRegText");
    const spinner = document.getElementById("btnRegSpinner");

    const payload = {
        email: document.getElementById("regEmail").value.trim(),
        password: document.getElementById("regPwd").value,
        invite_code: document.getElementById("regInvite").value.trim()
    };

    if (!payload.email || !payload.password) {
        showToast("请输入完整信息", "邮箱和密码均为必填项", "warning");
        return;
    }

    btn.disabled = true;
    text.style.display = "none";
    spinner.style.display = "inline-block";

    try {
        const res = await fetch(`${API_BASE}/user/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.ok) {
            showToast("注册成功", data.msg, "success");
            switchAuthTab(0);
            document.getElementById("loginEmail").value = payload.email;
            document.getElementById("regEmail").value = "";
            document.getElementById("regPwd").value = "";
            document.getElementById("regInvite").value = "";
        } else {
            showToast("注册失败", data.msg, "error");
        }
    } catch (error) {
        showToast("网络错误", "无法连接到网关服务，请确认服务已启动", "error");
        console.error(error);
    } finally {
        btn.disabled = false;
        text.style.display = "inline";
        spinner.style.display = "none";
    }
}

// ==========================================================================
// Auth: Login
// ==========================================================================
async function doLogin() {
    const btn = document.getElementById("btnLogin");
    const text = document.getElementById("btnLoginText");
    const spinner = document.getElementById("btnLoginSpinner");

    const payload = {
        email: document.getElementById("loginEmail").value.trim(),
        password: document.getElementById("loginPwd").value
    };

    if (!payload.email || !payload.password) {
        showToast("请输入完整信息", "邮箱和密码均为必填项", "warning");
        return;
    }

    btn.disabled = true;
    text.style.display = "none";
    spinner.style.display = "inline-block";

    try {
        const res = await fetch(`${API_BASE}/user/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.ok) {
            currentEmail = payload.email;
            document.getElementById("totpEmailDisplay").textContent = payload.email;
            document.getElementById("authView").style.display = "none";
            document.getElementById("totpView").style.display = "block";

            // Focus first TOTP digit
            const firstDigit = document.querySelector(".totp-digit");
            if (firstDigit) setTimeout(() => firstDigit.focus(), 100);

            // Clear previous TOTP inputs
            document.querySelectorAll(".totp-digit").forEach(d => {
                d.value = "";
                d.classList.remove("filled");
            });

            showToast("验证码已发送", "请查看邮箱并输入 6 位动态验证码", "info");
        } else {
            showToast("登录失败", data.msg, "error");
        }
    } catch (error) {
        showToast("网络错误", "无法连接到网关服务，请确认服务已启动", "error");
        console.error(error);
    } finally {
        btn.disabled = false;
        text.style.display = "inline";
        spinner.style.display = "none";
    }
}

// ==========================================================================
// Auth: Verify TOTP
// ==========================================================================
async function verifyTotp() {
    const btn = document.getElementById("btnVerifyTotp");
    const text = document.getElementById("btnVerifyText");
    const spinner = document.getElementById("btnVerifySpinner");

    // Collect 6 digits
    const digits = document.querySelectorAll(".totp-digit");
    const code = Array.from(digits).map(d => d.value).join("");

    if (code.length !== 6) {
        showToast("验证码不完整", "请输入完整的 6 位验证码", "warning");
        return;
    }

    btn.disabled = true;
    text.style.display = "none";
    spinner.style.display = "inline-block";

    try {
        const res = await fetch(`${API_BASE}/user/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: currentEmail, code })
        });
        const data = await res.json();

        if (data.ok) {
            currentRole = data.role;

            // Transition to dashboard
            document.getElementById("totpView").style.display = "none";
            document.getElementById("authWrapper").style.display = "none";
            document.getElementById("dashboardView").classList.add("visible");

            // Update sidebar user info
            document.getElementById("sidebarUserEmail").textContent = currentEmail;
            document.getElementById("sidebarUserRole").textContent =
                currentRole === "admin" ? "系统管理员" : "普通用户";
            document.getElementById("userAvatar").textContent =
                currentEmail.charAt(0).toUpperCase();

            // Admin-specific elements
            if (currentRole === "admin") {
                document.getElementById("adminNavSection").style.display = "block";
            }

            showToast("认证成功", `欢迎回来！当前身份: ${currentRole === "admin" ? "系统管理员" : "普通用户"}`, "success");

            // Start device polling
            loadDevices();
            if (deviceInterval) clearInterval(deviceInterval);
            deviceInterval = setInterval(loadDevices, 3000);
        } else {
            showToast("验证失败", data.msg, "error");
            // Clear digits on failure
            digits.forEach(d => { d.value = ""; d.classList.remove("filled"); });
            if (digits[0]) digits[0].focus();
        }
    } catch (error) {
        showToast("网络错误", "验证请求失败，请检查网络连接", "error");
        console.error(error);
    } finally {
        btn.disabled = false;
        text.style.display = "inline";
        spinner.style.display = "none";
    }
}

// ==========================================================================
// Auth: Back to Login
// ==========================================================================
function backToLogin() {
    document.getElementById("totpView").style.display = "none";
    document.getElementById("authView").style.display = "block";
    document.querySelectorAll(".totp-digit").forEach(d => {
        d.value = "";
        d.classList.remove("filled");
    });
}

// ==========================================================================
// Logout
// ==========================================================================
function logout() {
    currentEmail = "";
    currentRole = "";

    if (deviceInterval) {
        clearInterval(deviceInterval);
        deviceInterval = null;
    }

    document.getElementById("dashboardView").classList.remove("visible");
    document.getElementById("authWrapper").style.display = "flex";
    document.getElementById("authView").style.display = "block";
    document.getElementById("totpView").style.display = "none";
    document.getElementById("adminNavSection").style.display = "none";

    // Clear device list
    document.getElementById("deviceList").innerHTML = "";
    updateStats([]);

    // Reset auth form
    document.getElementById("loginPwd").value = "";

    showToast("已退出登录", "您已安全退出网关监控系统", "info");
}

// ==========================================================================
// Device Registration (Admin)
// ==========================================================================
function openDeviceModal() {
    document.getElementById("deviceModal").classList.remove("hidden");
    document.getElementById("devUid").focus();
}

function closeDeviceModal() {
    document.getElementById("deviceModal").classList.add("hidden");
}

async function registerDevice() {
    const btn = document.getElementById("btnRegisterDevice");
    const text = document.getElementById("btnDeviceText");
    const spinner = document.getElementById("btnDeviceSpinner");

    const payload = {
        uid: document.getElementById("devUid").value.trim(),
        psk: document.getElementById("devPsk").value.trim()
    };

    if (!payload.uid || !payload.psk) {
        showToast("参数不完整", "请填写设备 UID 和预共享密钥", "warning");
        return;
    }

    btn.disabled = true;
    text.style.display = "none";
    spinner.style.display = "inline-block";

    try {
        const res = await fetch(`${API_BASE}/device/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.ok) {
            showToast("设备已授权", data.msg, "success");
            document.getElementById("devUid").value = "";
            document.getElementById("devPsk").value = "";
            closeDeviceModal();
            loadDevices();
        } else {
            showToast("授权失败", data.msg, "error");
        }
    } catch (error) {
        showToast("网络错误", "设备注册请求失败，请检查网络", "error");
        console.error(error);
    } finally {
        btn.disabled = false;
        text.style.display = "inline";
        spinner.style.display = "none";
    }
}

// ==========================================================================
// Device List & Rendering
// ==========================================================================
async function loadDevices() {
    try {
        const res = await fetch(`${API_BASE}/devices`);
        const data = await res.json();
        renderDevices(data.data);
        updateStats(data.data);
        document.getElementById("sectionMeta").textContent =
            `最后刷新: ${new Date().toLocaleTimeString("zh-CN")}`;
    } catch (e) {
        console.warn("刷新设备列表失败:", e);
        document.getElementById("sectionMeta").textContent = "刷新失败，等待重试...";
    }
}

function renderDevices(devices) {
    const list = document.getElementById("deviceList");

    // Empty state
    if (!devices || devices.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="4" y="4" width="16" height="16" rx="2" ry="2"/>
                        <rect x="9" y="9" width="6" height="6"/>
                        <line x1="9" y1="1" x2="9" y2="4"/>
                        <line x1="15" y1="1" x2="15" y2="4"/>
                        <line x1="9" y1="20" x2="9" y2="23"/>
                        <line x1="15" y1="20" x2="15" y2="23"/>
                        <line x1="20" y1="9" x2="23" y2="9"/>
                        <line x1="20" y1="14" x2="23" y2="14"/>
                        <line x1="1" y1="9" x2="4" y2="9"/>
                        <line x1="1" y1="14" x2="4" y2="14"/>
                    </svg>
                </div>
                <h3>暂无设备</h3>
                <p>当前没有已授权的摄像头终端。如果您是管理员，请通过侧边栏"授权新设备"添加摄像头接入网关。</p>
            </div>
        `;
        return;
    }

    // Build device cards
    list.innerHTML = devices.map(dev => buildDeviceCard(dev)).join("");
}

function buildDeviceCard(dev) {
    const isOnline = dev.status === "online";
    const statusClass = isOnline ? "live" : "offline";
    const statusText = isOnline ? "推流中" : "未连接";
    const dotClass = isOnline ? "online" : "offline";

    const feedContent = isOnline
        ? `<img src="${API_BASE}/video/${dev.uid}" alt="Camera ${dev.uid}" onerror="this.parentElement.innerHTML='<div class=\\'feed-offline\\'><svg width=\\'32\\' height=\\'32\\' viewBox=\\'0 0 24 24\\' fill=\\'none\\' stroke=\\'currentColor\\' stroke-width=\\'1.5\\'><path d=\\'M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z\\'/><circle cx=\\'12\\' cy=\\'13\\' r=\\'4\\'/></svg><span>视频流连接中...</span></div>'">`
        : `<div class="feed-offline">
               <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                   <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>
                   <line x1="1" y1="1" x2="23" y2="23"/>
               </svg>
               <span>设备离线 · 无信号输入</span>
           </div>`;

    return `
        <div class="device-card">
            <div class="device-card-header">
                <div class="dev-name">
                    <span class="dev-icon ${dotClass}"></span>
                    终端: ${escapeHtml(dev.uid)}
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    ${isOnline ? `<button class="btn-snapshot" onclick="takeSnapshot('${escapeHtml(dev.uid)}'); event.stopPropagation();" title="抓拍当前画面">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
                        抓拍
                    </button>` : ""}
                    <span class="status-badge ${statusClass}">
                        ${isOnline ? '<span class="status-dot"></span>' : ""}
                        ${statusText}
                    </span>
                    ${isOnline ? '<span class="rec-dot" title="录像中"></span>' : ""}
                </div>
            </div>
            <div class="device-feed">
                <span class="feed-overlay">${escapeHtml(dev.uid)}</span>
                ${feedContent}
            </div>
            <div class="device-card-footer">
                <span class="dev-meta">UID: ${escapeHtml(dev.uid)}</span>
                <span class="dev-meta">${isOnline ? "MJPEG · ~20 FPS" : "最后在线: --"}</span>
            </div>
        </div>
    `;
}

function updateStats(devices) {
    const total = devices.length;
    const online = devices.filter(d => d.status === "online").length;
    const offline = total - online;

    document.getElementById("statTotal").textContent = total;
    document.getElementById("statOnline").textContent = online;
    document.getElementById("statOffline").textContent = offline;

    // Update nav badges
    document.getElementById("navOnlineCount").textContent = online;
    document.getElementById("navTotalCount").textContent = total;
}

// ==========================================================================
// Uptime Clock
// ==========================================================================
function startUptimeClock() {
    setInterval(() => {
        const elapsed = Math.floor((Date.now() - systemStartTime) / 1000);
        const h = Math.floor(elapsed / 3600);
        const m = Math.floor((elapsed % 3600) / 60);
        const s = elapsed % 60;
        document.getElementById("statUptime").textContent =
            `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    }, 1000);
}

// ==========================================================================
// Mobile Sidebar Toggle
// ==========================================================================
function toggleSidebar() {
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebarOverlay");
    const isOpen = sidebar.classList.contains("open");

    sidebar.classList.toggle("open", !isOpen);
    overlay.classList.toggle("visible", !isOpen);
}

// ==========================================================================
// Page Switching
// ==========================================================================
let currentPage = "monitor";

function switchPage(page) {
    currentPage = page;

    // Hide all content panels
    const isPlayback = page === "playback";
    const isAlerts = page === "alerts";

    document.getElementById("deviceList").style.display =
        (isPlayback || isAlerts) ? "none" : "";
    document.getElementById("playbackPanel").classList.toggle("visible", isPlayback);
    document.getElementById("alertsPanel").classList.toggle("visible", isAlerts);
    document.querySelector(".section-header").style.display =
        (isPlayback || isAlerts) ? "none" : "";
    document.getElementById("statGrid").style.display =
        (isPlayback || isAlerts) ? "none" : "";

    // Update topbar title
    const titles = {
        monitor: "实时监控画面",
        devices: "全部设备",
        playback: "录像回放",
        alerts: "安全告警"
    };
    document.querySelector(".topbar-left h2").textContent = titles[page] || "监控中心";

    if (page === "playback") {
        populatePlaybackDevices();
        loadStorageStats();
    }

    if (page === "alerts") {
        // 安全告警页面（人脸识别功能已移除，保留页面框架供后续扩展）
        document.getElementById("alertList").innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                    </svg>
                </div>
                <h3>安全告警</h3>
                <p>人脸识别功能已暂时关闭，此页面将在功能优化后重新开放</p>
            </div>`;
        document.getElementById("alertsMeta").textContent = "功能维护中";
        document.getElementById("knownFacesGrid").innerHTML = '<p class="text-muted" style="grid-column:1/-1;">功能维护中</p>';
        document.getElementById("riskFramesGrid").innerHTML = '<p class="text-muted" style="grid-column:1/-1;">功能维护中</p>';
    }
}

// ==========================================================================
// Playback Functions
// ==========================================================================
async function populatePlaybackDevices() {
    const select = document.getElementById("playbackDeviceSelect");
    try {
        const res = await fetch(`${API_BASE}/devices`);
        const data = await res.json();
        select.innerHTML = '<option value="">-- 选择摄像头 --</option>' +
            data.data.map(d => `<option value="${escapeHtml(d.uid)}">${escapeHtml(d.uid)} ${d.status === 'online' ? '● 在线' : '○ 离线'}</option>`).join("");

        // Clear date/hour selections
        document.getElementById("dateChipList").innerHTML = '<span class="chip-placeholder">请先选择设备</span>';
        document.getElementById("hourChipList").innerHTML = '<span class="chip-placeholder">请先选择日期</span>';
        resetPlaybackPlayer();
    } catch (e) {
        console.warn("加载设备列表失败:", e);
    }
}

async function onPlaybackDeviceChange(uid) {
    document.getElementById("dateChipList").innerHTML = '<span class="chip-placeholder">加载中...</span>';
    document.getElementById("hourChipList").innerHTML = '<span class="chip-placeholder">请先选择日期</span>';
    resetPlaybackPlayer();

    if (!uid) {
        document.getElementById("dateChipList").innerHTML = '<span class="chip-placeholder">请先选择设备</span>';
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/recordings/${encodeURIComponent(uid)}`);
        const data = await res.json();
        renderDateChips(data.data || []);
    } catch (e) {
        console.warn("加载录像日期失败:", e);
        document.getElementById("dateChipList").innerHTML = '<span class="chip-placeholder">加载失败</span>';
    }
}

function renderDateChips(dates) {
    const container = document.getElementById("dateChipList");
    if (!dates || dates.length === 0) {
        container.innerHTML = '<span class="chip-placeholder">该设备暂无录像</span>';
        return;
    }
    container.innerHTML = dates.map((d, i) =>
        `<span class="chip${i === 0 ? ' active' : ''}" data-date="${d}" onclick="selectDate(this, '${d}')">${formatDate(d)}</span>`
    ).join("");

    // Auto-select first date
    if (dates.length > 0) {
        selectDate(container.querySelector(".chip"), dates[0]);
    }
}

function formatDate(dateStr) {
    const parts = dateStr.split("-");
    return `${parts[1]}月${parts[2]}日`;
}

function selectDate(chipEl, dateStr) {
    // Highlight active chip
    document.querySelectorAll("#dateChipList .chip").forEach(c => c.classList.remove("active"));
    if (chipEl) chipEl.classList.add("active");

    // Load hours
    const uid = document.getElementById("playbackDeviceSelect").value;
    document.getElementById("hourChipList").innerHTML = '<span class="chip-placeholder">加载中...</span>';
    resetPlaybackPlayer();

    fetch(`${API_BASE}/recordings/${encodeURIComponent(uid)}/${dateStr}`)
        .then(r => r.json())
        .then(data => renderHourChips(data.data || [], dateStr))
        .catch(e => {
            console.warn("加载时段失败:", e);
            document.getElementById("hourChipList").innerHTML = '<span class="chip-placeholder">加载失败</span>';
        });
}

function renderHourChips(hours, dateStr) {
    const container = document.getElementById("hourChipList");
    if (!hours || hours.length === 0) {
        container.innerHTML = '<span class="chip-placeholder">该日期暂无录像</span>';
        return;
    }
    container.innerHTML = hours.map((h, i) =>
        `<span class="chip${i === 0 ? ' active' : ''}" data-hour="${h}" onclick="selectHour(this, '${h}', '${dateStr}')">${h}:00 - ${parseInt(h)+1}:00</span>`
    ).join("");

    // Auto-select first hour
    if (hours.length > 0) {
        selectHour(container.querySelector(".chip"), hours[0], dateStr);
    }
}

function selectHour(chipEl, hourStr, dateStr) {
    document.querySelectorAll("#hourChipList .chip").forEach(c => c.classList.remove("active"));
    if (chipEl) chipEl.classList.add("active");

    const uid = document.getElementById("playbackDeviceSelect").value;
    startPlayback(uid, dateStr, hourStr);
}

function startPlayback(uid, date, hour) {
    const player = document.getElementById("playbackPlayer");
    const placeholder = document.getElementById("playerPlaceholder");
    const img = document.getElementById("playbackImg");

    // Remove existing overlay if any
    const existingOverlay = player.querySelector(".player-overlay");
    if (existingOverlay) existingOverlay.remove();

    // Add overlay with info
    const overlay = document.createElement("div");
    overlay.className = "player-overlay";
    overlay.innerHTML = `
        <span class="player-tag">${escapeHtml(uid)}</span>
        <span class="player-tag">${date} ${hour}:00</span>
    `;
    player.appendChild(overlay);

    placeholder.style.display = "none";
    img.style.display = "block";
    img.src = `${API_BASE}/playback/${encodeURIComponent(uid)}/${date}/${hour}`;
}

function resetPlaybackPlayer() {
    const player = document.getElementById("playbackPlayer");
    const placeholder = document.getElementById("playerPlaceholder");
    const img = document.getElementById("playbackImg");

    img.src = "";
    img.style.display = "none";
    placeholder.style.display = "flex";

    const existingOverlay = player.querySelector(".player-overlay");
    if (existingOverlay) existingOverlay.remove();
}

// ==========================================================================
// Storage Statistics
// ==========================================================================
async function loadStorageStats() {
    const container = document.getElementById("storageStatsContent");
    try {
        const res = await fetch(`${API_BASE}/recordings/stats`);
        const data = await res.json();
        renderStorageStats(data.data);
    } catch (e) {
        console.warn("加载存储统计失败:", e);
        container.innerHTML = '<p class="text-muted">加载失败</p>';
    }
}

function renderStorageStats(stats) {
    const container = document.getElementById("storageStatsContent");
    const devices = stats.devices || {};
    const deviceIds = Object.keys(devices);

    if (deviceIds.length === 0) {
        container.innerHTML = '<p class="text-muted">暂无录像数据</p>';
        return;
    }

    const maxSize = Math.max(1, ...deviceIds.map(id => devices[id].size_bytes));

    let html = `
        <table class="storage-table">
            <thead>
                <tr>
                    <th>设备</th>
                    <th>帧数</th>
                    <th>大小</th>
                    <th>占用比例</th>
                    <th>录像范围</th>
                    <th>状态</th>
                </tr>
            </thead>
            <tbody>
    `;

    deviceIds.forEach(id => {
        const dev = devices[id];
        const pct = Math.round((dev.size_bytes / maxSize) * 100);
        const barWidth = Math.max(pct, 3); // minimum 3% for visibility

        html += `
            <tr>
                <td style="font-family:var(--font-mono);font-weight:600;">${escapeHtml(id)}</td>
                <td>${dev.frame_count.toLocaleString()}</td>
                <td>${formatSize(dev.size_bytes)}</td>
                <td style="min-width:120px;">
                    <div class="size-bar-bg"><div class="size-bar-fill" style="width:${barWidth}%"></div></div>
                </td>
                <td style="font-size:11px;">${dev.oldest_date || '--'} ~ ${dev.newest_date || '--'}</td>
                <td>
                    <button class="recording-toggle ${dev.recording ? 'on' : 'off'}"
                            onclick="toggleRecording('${escapeHtml(id)}')">
                        ${dev.recording ? '● 录制中' : '○ 已暂停'}
                    </button>
                </td>
            </tr>
        `;
    });

    html += `
            </tbody>
        </table>
        <p style="margin-top:12px;font-size:12px;color:var(--gray-500);">
            总计: ${formatSize(stats.total_size_bytes)} · ${deviceIds.length} 个设备
        </p>
    `;

    container.innerHTML = html;
}

function formatSize(bytes) {
    if (bytes === 0) return "0 B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

async function toggleRecording(uid) {
    try {
        const res = await fetch(`${API_BASE}/recordings/toggle/${encodeURIComponent(uid)}`, {
            method: "POST"
        });
        const data = await res.json();
        showToast(
            data.recording ? "录像已开启" : "录像已暂停",
            data.msg,
            data.recording ? "success" : "warning"
        );
        // Refresh stats
        loadStorageStats();
    } catch (e) {
        showToast("操作失败", "无法切换录像状态", "error");
        console.error(e);
    }
}

// ==========================================================================
// Snapshot
// ==========================================================================
function takeSnapshot(uid) {
    const url = `${API_BASE}/snapshot/${encodeURIComponent(uid)}`;
    // Create a temporary anchor to trigger download
    const a = document.createElement("a");
    a.href = url;
    a.download = `snapshot_${uid}_${new Date().toISOString().replace(/[:.]/g, '-')}.jpg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast("抓拍成功", `设备 ${uid} 的当前画面已开始下载`, "success", 2000);
}

// ==========================================================================
// Utilities
// ==========================================================================
function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}
