// =========================================================================
// i18n — 4 languages (en / zh-CN / zh-TW / ja).
//
// The active language is resolved synchronously in <head> (window.__LANG__):
// a manual choice (localStorage 'dn7_lang') wins; otherwise the browser
// language, falling back to English. This module supplies the dictionary +
// `tr(key)`, translates static [data-i18n*] nodes, wires the language switcher,
// and then reveals the page (data-i18n-ready) — so the UI only ever paints in
// the correct language (no flash). Switching language persists the choice and
// reloads, so every view re-renders in the new language with no half state.
// =========================================================================
const I18N = {
  en: {
    'common.cancel': 'Cancel', 'common.ok': 'OK', 'common.confirm': 'Please confirm',
    'common.saved': 'Saved', 'common.loadfail': 'Failed to load: ',
    'common.restart_hint': ' (port/toggle changes take effect after restarting Panel)',
    'login.title': 'SIGN IN', 'login.sub': 'Sign in securely to the local console',
    'login.account': 'Account', 'login.password': 'Password',
    'login.ph_account': 'Please enter your account', 'login.ph_password': 'Please enter your password',
    'login.submit': 'Sign in', 'login.err_conn': 'Cannot reach the server', 'login.err_fail': 'Login failed',
    'tab.dash': 'Monitor', 'tab.term': 'Terminal', 'tab.files': 'Files', 'tab.settings': 'Settings',
    'shell.logout': 'Sign out', 'shell.update_hint': 'Click to check for updates',
    'theme.tip': 'Theme: ', 'theme.auto': 'Auto', 'theme.light': 'Light', 'theme.dark': 'Dark',
    'lang.name': 'Language',
    'dash.mem': 'Memory', 'dash.disk': 'Disk', 'dash.cores': ' cores', 'dash.vcpu': ' vCPU',
    'dash.proc': 'Process', 'dash.user': 'User', 'dash.up': 'Up', 'dash.dn': 'Down', 'dash.net': 'Network',
    'set.account_sec': 'Login account', 'set.account': 'Account', 'set.password': 'Password',
    'set.pw_ph': 'Leave blank to keep unchanged',
    'set.pw_forgot_a': 'Forgot it? Run', 'set.pw_forgot_b': 'on the host to reset.',
    'set.show': 'Show', 'set.hide': 'Hide', 'set.pw_len': 'Password length must be 6-128',
    'set.port_sec': 'Port (restart Panel to apply)',
    'set.enable': 'Enable local management (restart required after disabling)',
    'set.save': 'Save', 'set.appearance': 'Appearance & branding', 'set.panel_name': 'Panel name',
    'set.logo_label': 'Logo (login + sidebar; square transparent PNG/SVG, ≤512KB)',
    'set.choose_img': 'Choose image', 'set.restore_default': 'Restore default',
    'set.accent': 'Accent color', 'set.default_paren': '(default)',
    'set.default_theme': 'Default theme (new visitors; a user’s own choice wins)',
    'set.save_appearance': 'Save appearance', 'set.img_too_big': 'Image too large (max 512KB)',
    'set.saving_refresh': 'Saved, refreshing…', 'set.language': 'Language',
    'common.stopped': 'Stopped', 'common.started': 'Started', 'common.restarted': 'Restarted', 'common.deleted': 'Deleted', 'common.created': 'Created', 'common.applied': 'Applied',
    'my.detecting': 'Checking environment', 'my.creating': 'Creating database',
    'my.need_docker': 'Install and start Docker first (under Docker management). Databases are managed by DN7 Panel via containers.',
    'my.none_desc': 'No database yet. DN7 Panel hosts one instance per machine; create multiple databases inside it.',
    'my.create_db': 'Create database', 'my.phase_init': 'Initializing', 'my.phase_running': 'Running', 'my.phase_stopped': 'Stopped',
    'my.port': 'Port', 'my.port_unmapped': 'not mapped', 'my.stop': 'Stop', 'my.restart': 'Restart', 'my.start': 'Start', 'my.delete': 'Delete',
    'my.not_running': 'Instance not running; start it to manage databases and accounts',
    'my.del_title': 'Delete database', 'my.del_desc': 'Deleting removes the database container. Keep the data volume (all databases and data in it)?',
    'my.keep_data': 'Keep data', 'my.drop_with_data': 'Delete with data', 'my.engine_version': 'Engine / version',
    'my.ext_port': 'External port (maps 3306)', 'my.expose': 'Map port externally',
    'my.root_auto': 'The root password is generated automatically and can be viewed under “Settings”. You can create multiple databases in the instance.',
    'my.create': 'Create', 'my.db_created': 'Database created',
    'my.tab_db': 'Databases', 'my.tab_users': 'Accounts', 'my.tab_settings': 'Settings',
    'my.host': 'Host', 'my.user': 'User', 'my.password': 'Password', 'my.new_db': 'New database', 'my.db_name': 'Database name',
    'my.tables': 'Tables', 'my.size': 'Size', 'my.actions': 'Actions', 'my.system': 'system', 'my.none': 'none',
    'my.confirm_drop_db': 'Delete database {db}? This erases all data in it.',
    'my.new_user': 'New account', 'my.username': 'Username', 'my.src_host': 'Source host',
    'my.confirm_drop_user': 'Delete account {u}@{h}?',
    'my.reset_root': 'Reset root password', 'my.reset_show': 'Reset and show new password',
    'my.port_map': 'Port mapping', 'my.expose_short': 'Map externally', 'my.apply_recreate': 'Apply (recreate container)',
    'my.backup': 'Backup', 'my.export_dump': 'Export mysqldump', 'my.new_root_pw': 'New root password: ',
    'dk.detecting': 'Checking Docker', 'dk.installing': 'Installing Docker', 'dk.not_found': 'No Docker daemon detected on this host.',
    'dk.install_method': 'Install method', 'dk.ch_distro': 'Distro package docker.io (recommended, most stable, uses system mirrors)', 'dk.ch_ce': 'Official latest docker-ce',
    'dk.network_region': 'Network / region', 'dk.rg_auto': 'Auto-detect', 'dk.rg_cn': 'China (mirror acceleration)', 'dk.rg_global': 'Overseas (official source)',
    'dk.install_btn': 'Install Docker', 'dk.tab_containers': 'Containers', 'dk.tab_images': 'Images', 'dk.tab_networks': 'Networks',
    'dk.create_container': 'Create container', 'dk.refresh': 'Refresh', 'dk.no_containers': 'No containers',
    'dk.col_name': 'Name', 'dk.col_image': 'Image', 'dk.col_status': 'Status', 'dk.col_ports': 'Ports', 'dk.col_actions': 'Actions',
    'dk.builtin': 'built-in', 'dk.stop': 'Stop', 'dk.restart': 'Restart', 'dk.terminal': 'Terminal', 'dk.files': 'Files', 'dk.start': 'Start', 'dk.logs': 'Logs', 'dk.networks': 'Networks', 'dk.delete': 'Delete',
    'dk.ctn_term': 'Container terminal · ', 'dk.ctn_files': 'Container files · ',
    'dk.confirm_rm_ctn': 'Delete container {name}?', 'dk.op_ok': 'Done', 'dk.logs_title': 'Logs · ', 'dk.empty_log': '(empty)',
    'dk.net_title': 'Networks · ', 'dk.connected': 'Connected', 'dk.disconnect': 'Disconnect', 'dk.connectable': 'Available', 'dk.connect': 'Connect', 'dk.none': 'none',
    'dk.image': 'Image', 'dk.image_ph': 'Pick or type an image, e.g. nginx:latest', 'dk.ctn_name': 'Container name (optional)', 'dk.restart_policy': 'Restart policy',
    'dk.port_map': 'Port mapping', 'dk.add_port': '+ Add port', 'dk.env': 'Environment variables', 'dk.add_env': '+ Add variable', 'dk.volumes': 'Volumes', 'dk.add_vol': '+ Add mount',
    'dk.start_cmd': 'Start command (optional)', 'dk.cmd_ph': 'Blank uses the image default', 'dk.alloc_tty': 'Allocate TTY', 'dk.start_after': 'Start after create',
    'dk.create': 'Create', 'dk.need_image': 'Please enter an image', 'dk.ctn_created': 'Container created',
    'dk.host_port': 'Host port', 'dk.container_port': 'Container port', 'dk.host_path': 'Host path /data/app', 'dk.container_path': 'Container path /app', 'dk.readonly': 'read-only',
    'dk.create_network': 'Create network', 'dk.net_name': 'Network name', 'dk.col_driver': 'Driver', 'dk.col_scope': 'Scope', 'dk.confirm_rm_net': 'Delete network {name}?',
    'dk.no_images': 'No images', 'dk.col_size': 'Size', 'dk.col_created': 'Created', 'dk.pull_image': 'Pull image', 'dk.confirm_rm_img': 'Delete image {name}?',
    'dk.img_name_label': 'Image name (e.g. nginx:latest)', 'dk.mirror_label': 'Accelerator mirror (optional)', 'dk.mirror_none': 'None', 'dk.pull_start': 'Start pull', 'dk.need_image_name': 'Please enter an image name', 'dk.pull_done': 'Pull complete',
  },
  'zh-CN': {
    'common.cancel': '取消', 'common.ok': '确定', 'common.confirm': '请确认',
    'common.saved': '已保存', 'common.loadfail': '加载失败：',
    'common.restart_hint': '（端口/开关改动需重启 Panel 生效）',
    'login.title': '登录', 'login.sub': '安全登录到本机控制台',
    'login.account': '账号', 'login.password': '密码',
    'login.ph_account': '请输入账号', 'login.ph_password': '请输入密码',
    'login.submit': '登 录', 'login.err_conn': '无法连接服务', 'login.err_fail': '登录失败',
    'tab.dash': '监控', 'tab.term': '终端', 'tab.files': '文件', 'tab.settings': '设置',
    'shell.logout': '退出登录', 'shell.update_hint': '点击查看更新',
    'theme.tip': '主题：', 'theme.auto': '跟随系统', 'theme.light': '浅色', 'theme.dark': '深色',
    'lang.name': '语言',
    'dash.mem': '内存', 'dash.disk': '磁盘', 'dash.cores': ' 核心', 'dash.vcpu': ' vCPU',
    'dash.proc': '进程', 'dash.user': '用户', 'dash.up': '上行', 'dash.dn': '下行', 'dash.net': '网络吞吐',
    'set.account_sec': '登录账号', 'set.account': '账号', 'set.password': '密码',
    'set.pw_ph': '留空表示不修改',
    'set.pw_forgot_a': '忘记密码？在主机上运行', 'set.pw_forgot_b': '重置账号密码。',
    'set.show': '显示', 'set.hide': '隐藏', 'set.pw_len': '密码长度需为 6-128',
    'set.port_sec': '端口（改后重启 Panel 生效）',
    'set.enable': '启用本机管理（关闭后需重启生效）',
    'set.save': '保存', 'set.appearance': '外观与品牌', 'set.panel_name': '面板名称',
    'set.logo_label': 'Logo（登录页与侧边栏，建议方形透明 PNG/SVG，≤512KB）',
    'set.choose_img': '选择图片', 'set.restore_default': '恢复默认',
    'set.accent': '主色调', 'set.default_paren': '（默认）',
    'set.default_theme': '默认主题（新访客；用户切换后以其选择为准）',
    'set.save_appearance': '保存外观', 'set.img_too_big': '图片过大（上限 512KB）',
    'set.saving_refresh': '已保存，正在刷新…', 'set.language': '语言',
    'common.stopped': '已停止', 'common.started': '已启动', 'common.restarted': '已重启', 'common.deleted': '已删除', 'common.created': '已创建', 'common.applied': '已应用',
    'my.detecting': '正在检测环境', 'my.creating': '正在创建数据库',
    'my.need_docker': '需要先安装并启动 Docker（在 Docker 管理中安装）。数据库由 DN7 Panel 通过容器管理。',
    'my.none_desc': '尚未创建数据库。一台主机由 DN7 Panel 托管一个实例，可在其中创建多个库。',
    'my.create_db': '创建数据库', 'my.phase_init': '初始化中', 'my.phase_running': '运行中', 'my.phase_stopped': '已停止',
    'my.port': '端口', 'my.port_unmapped': '未映射', 'my.stop': '停止', 'my.restart': '重启', 'my.start': '启动', 'my.delete': '删除',
    'my.not_running': '实例未运行，启动后可管理数据库与账号',
    'my.del_title': '删除数据库', 'my.del_desc': '删除将移除数据库容器。是否保留数据卷（其中的所有库和数据）？',
    'my.keep_data': '保留数据', 'my.drop_with_data': '连同数据删除', 'my.engine_version': '引擎 / 版本',
    'my.ext_port': '对外端口（映射 3306）', 'my.expose': '对外映射端口',
    'my.root_auto': 'root 密码将自动生成，可在「设置」中查看。创建后可在实例中建立多个数据库。',
    'my.create': '创建', 'my.db_created': '数据库已创建',
    'my.tab_db': '数据库', 'my.tab_users': '账号', 'my.tab_settings': '设置',
    'my.host': '主机', 'my.user': '用户', 'my.password': '密码', 'my.new_db': '新建数据库', 'my.db_name': '库名',
    'my.tables': '表数', 'my.size': '大小', 'my.actions': '操作', 'my.system': '系统', 'my.none': '无',
    'my.confirm_drop_db': '删除数据库 {db}？此操作会清空其中所有数据。',
    'my.new_user': '新建账号', 'my.username': '用户名', 'my.src_host': '来源主机',
    'my.confirm_drop_user': '删除账号 {u}@{h}？',
    'my.reset_root': '重置 root 密码', 'my.reset_show': '重置并显示新密码',
    'my.port_map': '端口映射', 'my.expose_short': '对外映射', 'my.apply_recreate': '应用（重建容器）',
    'my.backup': '备份', 'my.export_dump': '导出 mysqldump', 'my.new_root_pw': '新 root 密码：',
    'dk.detecting': '正在检测 Docker', 'dk.installing': '正在安装 Docker', 'dk.not_found': '本机未检测到 Docker 守护进程。',
    'dk.install_method': '安装方式', 'dk.ch_distro': '系统自带 docker.io（推荐，最稳，走系统镜像）', 'dk.ch_ce': '官方最新 docker-ce',
    'dk.network_region': '网络 / 地区', 'dk.rg_auto': '自动检测', 'dk.rg_cn': '国内（镜像加速）', 'dk.rg_global': '海外（官方源）',
    'dk.install_btn': '一键安装 Docker', 'dk.tab_containers': '容器', 'dk.tab_images': '镜像', 'dk.tab_networks': '网络',
    'dk.create_container': '创建容器', 'dk.refresh': '刷新', 'dk.no_containers': '暂无容器',
    'dk.col_name': '名称', 'dk.col_image': '镜像', 'dk.col_status': '状态', 'dk.col_ports': '端口', 'dk.col_actions': '操作',
    'dk.builtin': '内置', 'dk.stop': '停止', 'dk.restart': '重启', 'dk.terminal': '终端', 'dk.files': '文件', 'dk.start': '启动', 'dk.logs': '日志', 'dk.networks': '网络', 'dk.delete': '删除',
    'dk.ctn_term': '容器终端 · ', 'dk.ctn_files': '容器文件 · ',
    'dk.confirm_rm_ctn': '删除容器 {name}？', 'dk.op_ok': '操作成功', 'dk.logs_title': '日志 · ', 'dk.empty_log': '(空)',
    'dk.net_title': '网络 · ', 'dk.connected': '已连接', 'dk.disconnect': '断开', 'dk.connectable': '可连接', 'dk.connect': '连接', 'dk.none': '无',
    'dk.image': '镜像', 'dk.image_ph': '选择或输入镜像，如 nginx:latest', 'dk.ctn_name': '容器名（可选）', 'dk.restart_policy': '重启策略',
    'dk.port_map': '端口映射', 'dk.add_port': '+ 添加端口', 'dk.env': '环境变量', 'dk.add_env': '+ 添加变量', 'dk.volumes': '挂载卷', 'dk.add_vol': '+ 添加挂载',
    'dk.start_cmd': '启动命令（可选）', 'dk.cmd_ph': '留空用镜像默认', 'dk.alloc_tty': '分配终端', 'dk.start_after': '创建后启动',
    'dk.create': '创建', 'dk.need_image': '请输入镜像', 'dk.ctn_created': '容器已创建',
    'dk.host_port': '宿主端口', 'dk.container_port': '容器端口', 'dk.host_path': '宿主路径 /data/app', 'dk.container_path': '容器路径 /app', 'dk.readonly': '只读',
    'dk.create_network': '创建网络', 'dk.net_name': '网络名', 'dk.col_driver': '驱动', 'dk.col_scope': '范围', 'dk.confirm_rm_net': '删除网络 {name}？',
    'dk.no_images': '暂无镜像', 'dk.col_size': '大小', 'dk.col_created': '创建', 'dk.pull_image': '拉取镜像', 'dk.confirm_rm_img': '删除镜像 {name}？',
    'dk.img_name_label': '镜像名（如 nginx:latest）', 'dk.mirror_label': '加速镜像源（可选）', 'dk.mirror_none': '不使用', 'dk.pull_start': '开始拉取', 'dk.need_image_name': '请输入镜像名', 'dk.pull_done': '拉取完成',
  },
  'zh-TW': {
    'common.cancel': '取消', 'common.ok': '確定', 'common.confirm': '請確認',
    'common.saved': '已儲存', 'common.loadfail': '載入失敗：',
    'common.restart_hint': '（連接埠/開關變更需重啟 Panel 生效）',
    'login.title': '登入', 'login.sub': '安全登入本機主控台',
    'login.account': '帳號', 'login.password': '密碼',
    'login.ph_account': '請輸入帳號', 'login.ph_password': '請輸入密碼',
    'login.submit': '登 入', 'login.err_conn': '無法連線到服務', 'login.err_fail': '登入失敗',
    'tab.dash': '監控', 'tab.term': '終端機', 'tab.files': '檔案', 'tab.settings': '設定',
    'shell.logout': '登出', 'shell.update_hint': '點擊查看更新',
    'theme.tip': '主題：', 'theme.auto': '跟隨系統', 'theme.light': '淺色', 'theme.dark': '深色',
    'lang.name': '語言',
    'dash.mem': '記憶體', 'dash.disk': '磁碟', 'dash.cores': ' 核心', 'dash.vcpu': ' vCPU',
    'dash.proc': '程序', 'dash.user': '使用者', 'dash.up': '上行', 'dash.dn': '下行', 'dash.net': '網路吞吐',
    'set.account_sec': '登入帳號', 'set.account': '帳號', 'set.password': '密碼',
    'set.pw_ph': '留空表示不修改',
    'set.pw_forgot_a': '忘記密碼？在主機上執行', 'set.pw_forgot_b': '重設帳號密碼。',
    'set.show': '顯示', 'set.hide': '隱藏', 'set.pw_len': '密碼長度需為 6-128',
    'set.port_sec': '連接埠（變更後重啟 Panel 生效）',
    'set.enable': '啟用本機管理（停用後需重啟生效）',
    'set.save': '儲存', 'set.appearance': '外觀與品牌', 'set.panel_name': '面板名稱',
    'set.logo_label': 'Logo（登入頁與側邊欄，建議方形透明 PNG/SVG，≤512KB）',
    'set.choose_img': '選擇圖片', 'set.restore_default': '恢復預設',
    'set.accent': '主色調', 'set.default_paren': '（預設）',
    'set.default_theme': '預設主題（新訪客；使用者切換後以其選擇為準）',
    'set.save_appearance': '儲存外觀', 'set.img_too_big': '圖片過大（上限 512KB）',
    'set.saving_refresh': '已儲存，正在重新整理…', 'set.language': '語言',
    'common.stopped': '已停止', 'common.started': '已啟動', 'common.restarted': '已重啟', 'common.deleted': '已刪除', 'common.created': '已建立', 'common.applied': '已套用',
    'my.detecting': '正在偵測環境', 'my.creating': '正在建立資料庫',
    'my.need_docker': '需先安裝並啟動 Docker（於 Docker 管理中安裝）。資料庫由 DN7 Panel 透過容器管理。',
    'my.none_desc': '尚未建立資料庫。一台主機由 DN7 Panel 託管一個實例，可在其中建立多個資料庫。',
    'my.create_db': '建立資料庫', 'my.phase_init': '初始化中', 'my.phase_running': '執行中', 'my.phase_stopped': '已停止',
    'my.port': '連接埠', 'my.port_unmapped': '未對應', 'my.stop': '停止', 'my.restart': '重啟', 'my.start': '啟動', 'my.delete': '刪除',
    'my.not_running': '實例未執行，啟動後可管理資料庫與帳號',
    'my.del_title': '刪除資料庫', 'my.del_desc': '刪除將移除資料庫容器。是否保留資料卷（其中的所有資料庫與資料）？',
    'my.keep_data': '保留資料', 'my.drop_with_data': '連同資料刪除', 'my.engine_version': '引擎 / 版本',
    'my.ext_port': '對外連接埠（對應 3306）', 'my.expose': '對外對應連接埠',
    'my.root_auto': 'root 密碼將自動產生，可於「設定」中查看。建立後可在實例中建立多個資料庫。',
    'my.create': '建立', 'my.db_created': '資料庫已建立',
    'my.tab_db': '資料庫', 'my.tab_users': '帳號', 'my.tab_settings': '設定',
    'my.host': '主機', 'my.user': '使用者', 'my.password': '密碼', 'my.new_db': '新增資料庫', 'my.db_name': '資料庫名稱',
    'my.tables': '資料表數', 'my.size': '大小', 'my.actions': '操作', 'my.system': '系統', 'my.none': '無',
    'my.confirm_drop_db': '刪除資料庫 {db}？此操作會清空其中所有資料。',
    'my.new_user': '新增帳號', 'my.username': '使用者名稱', 'my.src_host': '來源主機',
    'my.confirm_drop_user': '刪除帳號 {u}@{h}？',
    'my.reset_root': '重設 root 密碼', 'my.reset_show': '重設並顯示新密碼',
    'my.port_map': '連接埠對應', 'my.expose_short': '對外對應', 'my.apply_recreate': '套用（重建容器）',
    'my.backup': '備份', 'my.export_dump': '匯出 mysqldump', 'my.new_root_pw': '新 root 密碼：',
    'dk.detecting': '正在偵測 Docker', 'dk.installing': '正在安裝 Docker', 'dk.not_found': '本機未偵測到 Docker 守護程序。',
    'dk.install_method': '安裝方式', 'dk.ch_distro': '系統內建 docker.io（推薦，最穩，走系統鏡像）', 'dk.ch_ce': '官方最新 docker-ce',
    'dk.network_region': '網路 / 地區', 'dk.rg_auto': '自動偵測', 'dk.rg_cn': '中國大陸（鏡像加速）', 'dk.rg_global': '海外（官方來源）',
    'dk.install_btn': '一鍵安裝 Docker', 'dk.tab_containers': '容器', 'dk.tab_images': '映像', 'dk.tab_networks': '網路',
    'dk.create_container': '建立容器', 'dk.refresh': '重新整理', 'dk.no_containers': '尚無容器',
    'dk.col_name': '名稱', 'dk.col_image': '映像', 'dk.col_status': '狀態', 'dk.col_ports': '連接埠', 'dk.col_actions': '操作',
    'dk.builtin': '內建', 'dk.stop': '停止', 'dk.restart': '重啟', 'dk.terminal': '終端機', 'dk.files': '檔案', 'dk.start': '啟動', 'dk.logs': '日誌', 'dk.networks': '網路', 'dk.delete': '刪除',
    'dk.ctn_term': '容器終端機 · ', 'dk.ctn_files': '容器檔案 · ',
    'dk.confirm_rm_ctn': '刪除容器 {name}？', 'dk.op_ok': '操作成功', 'dk.logs_title': '日誌 · ', 'dk.empty_log': '(空)',
    'dk.net_title': '網路 · ', 'dk.connected': '已連接', 'dk.disconnect': '中斷', 'dk.connectable': '可連接', 'dk.connect': '連接', 'dk.none': '無',
    'dk.image': '映像', 'dk.image_ph': '選擇或輸入映像，如 nginx:latest', 'dk.ctn_name': '容器名稱（選填）', 'dk.restart_policy': '重啟策略',
    'dk.port_map': '連接埠對應', 'dk.add_port': '+ 新增連接埠', 'dk.env': '環境變數', 'dk.add_env': '+ 新增變數', 'dk.volumes': '掛載磁碟區', 'dk.add_vol': '+ 新增掛載',
    'dk.start_cmd': '啟動指令（選填）', 'dk.cmd_ph': '留空使用映像預設', 'dk.alloc_tty': '配置終端機', 'dk.start_after': '建立後啟動',
    'dk.create': '建立', 'dk.need_image': '請輸入映像', 'dk.ctn_created': '容器已建立',
    'dk.host_port': '主機連接埠', 'dk.container_port': '容器連接埠', 'dk.host_path': '主機路徑 /data/app', 'dk.container_path': '容器路徑 /app', 'dk.readonly': '唯讀',
    'dk.create_network': '建立網路', 'dk.net_name': '網路名稱', 'dk.col_driver': '驅動', 'dk.col_scope': '範圍', 'dk.confirm_rm_net': '刪除網路 {name}？',
    'dk.no_images': '尚無映像', 'dk.col_size': '大小', 'dk.col_created': '建立時間', 'dk.pull_image': '拉取映像', 'dk.confirm_rm_img': '刪除映像 {name}？',
    'dk.img_name_label': '映像名稱（如 nginx:latest）', 'dk.mirror_label': '加速鏡像來源（選填）', 'dk.mirror_none': '不使用', 'dk.pull_start': '開始拉取', 'dk.need_image_name': '請輸入映像名稱', 'dk.pull_done': '拉取完成',
  },
  ja: {
    'common.cancel': 'キャンセル', 'common.ok': 'OK', 'common.confirm': '確認してください',
    'common.saved': '保存しました', 'common.loadfail': '読み込み失敗：',
    'common.restart_hint': '（ポート/スイッチの変更は Panel 再起動後に有効）',
    'login.title': 'サインイン', 'login.sub': 'ローカルコンソールに安全にサインイン',
    'login.account': 'アカウント', 'login.password': 'パスワード',
    'login.ph_account': 'アカウントを入力', 'login.ph_password': 'パスワードを入力',
    'login.submit': 'サインイン', 'login.err_conn': 'サーバーに接続できません', 'login.err_fail': 'ログインに失敗しました',
    'tab.dash': 'モニター', 'tab.term': 'ターミナル', 'tab.files': 'ファイル', 'tab.settings': '設定',
    'shell.logout': 'ログアウト', 'shell.update_hint': 'クリックして更新を確認',
    'theme.tip': 'テーマ：', 'theme.auto': 'システムに従う', 'theme.light': 'ライト', 'theme.dark': 'ダーク',
    'lang.name': '言語',
    'dash.mem': 'メモリ', 'dash.disk': 'ディスク', 'dash.cores': ' コア', 'dash.vcpu': ' vCPU',
    'dash.proc': 'プロセス', 'dash.user': 'ユーザー', 'dash.up': '上り', 'dash.dn': '下り', 'dash.net': 'ネットワーク',
    'set.account_sec': 'ログインアカウント', 'set.account': 'アカウント', 'set.password': 'パスワード',
    'set.pw_ph': '空欄なら変更しません',
    'set.pw_forgot_a': 'パスワードを忘れた場合、ホストで', 'set.pw_forgot_b': 'を実行して再設定します。',
    'set.show': '表示', 'set.hide': '非表示', 'set.pw_len': 'パスワードは6〜128文字',
    'set.port_sec': 'ポート（変更後 Panel 再起動で有効）',
    'set.enable': 'ローカル管理を有効化（無効化後は再起動が必要）',
    'set.save': '保存', 'set.appearance': '外観とブランド', 'set.panel_name': 'パネル名',
    'set.logo_label': 'ロゴ（ログイン＋サイドバー、正方形・透過 PNG/SVG、512KB以下）',
    'set.choose_img': '画像を選択', 'set.restore_default': '既定に戻す',
    'set.accent': 'アクセントカラー', 'set.default_paren': '（既定）',
    'set.default_theme': '既定テーマ（新規訪問者；ユーザーの選択が優先）',
    'set.save_appearance': '外観を保存', 'set.img_too_big': '画像が大きすぎます（上限512KB）',
    'set.saving_refresh': '保存しました。更新中…', 'set.language': '言語',
    'common.stopped': '停止しました', 'common.started': '起動しました', 'common.restarted': '再起動しました', 'common.deleted': '削除しました', 'common.created': '作成しました', 'common.applied': '適用しました',
    'my.detecting': '環境を確認中', 'my.creating': 'データベースを作成中',
    'my.need_docker': '先に Docker をインストールして起動してください（Docker 管理から）。データベースは DN7 Panel がコンテナで管理します。',
    'my.none_desc': 'データベースはまだありません。DN7 Panel は1台につき1インスタンスを管理し、その中に複数のデータベースを作成できます。',
    'my.create_db': 'データベースを作成', 'my.phase_init': '初期化中', 'my.phase_running': '実行中', 'my.phase_stopped': '停止中',
    'my.port': 'ポート', 'my.port_unmapped': '未マッピング', 'my.stop': '停止', 'my.restart': '再起動', 'my.start': '起動', 'my.delete': '削除',
    'my.not_running': 'インスタンス停止中。起動するとデータベースとアカウントを管理できます',
    'my.del_title': 'データベースを削除', 'my.del_desc': '削除するとデータベースコンテナが削除されます。データボリューム（すべてのDBとデータ）を保持しますか？',
    'my.keep_data': 'データを保持', 'my.drop_with_data': 'データごと削除', 'my.engine_version': 'エンジン / バージョン',
    'my.ext_port': '外部ポート（3306 にマッピング）', 'my.expose': 'ポートを外部公開',
    'my.root_auto': 'root パスワードは自動生成され、「設定」で確認できます。作成後、インスタンス内に複数のデータベースを作成できます。',
    'my.create': '作成', 'my.db_created': 'データベースを作成しました',
    'my.tab_db': 'データベース', 'my.tab_users': 'アカウント', 'my.tab_settings': '設定',
    'my.host': 'ホスト', 'my.user': 'ユーザー', 'my.password': 'パスワード', 'my.new_db': '新規データベース', 'my.db_name': 'データベース名',
    'my.tables': 'テーブル数', 'my.size': 'サイズ', 'my.actions': '操作', 'my.system': 'システム', 'my.none': 'なし',
    'my.confirm_drop_db': 'データベース {db} を削除しますか？中のすべてのデータが消去されます。',
    'my.new_user': '新規アカウント', 'my.username': 'ユーザー名', 'my.src_host': '接続元ホスト',
    'my.confirm_drop_user': 'アカウント {u}@{h} を削除しますか？',
    'my.reset_root': 'root パスワードをリセット', 'my.reset_show': 'リセットして新パスワードを表示',
    'my.port_map': 'ポートマッピング', 'my.expose_short': '外部公開', 'my.apply_recreate': '適用（コンテナ再作成）',
    'my.backup': 'バックアップ', 'my.export_dump': 'mysqldump をエクスポート', 'my.new_root_pw': '新しい root パスワード：',
    'dk.detecting': 'Docker を確認中', 'dk.installing': 'Docker をインストール中', 'dk.not_found': 'このホストで Docker デーモンが見つかりません。',
    'dk.install_method': 'インストール方法', 'dk.ch_distro': 'ディストリ標準 docker.io（推奨・最も安定・システムミラー利用）', 'dk.ch_ce': '公式最新 docker-ce',
    'dk.network_region': 'ネットワーク / 地域', 'dk.rg_auto': '自動検出', 'dk.rg_cn': '中国（ミラー高速化）', 'dk.rg_global': '海外（公式ソース）',
    'dk.install_btn': 'Docker をインストール', 'dk.tab_containers': 'コンテナ', 'dk.tab_images': 'イメージ', 'dk.tab_networks': 'ネットワーク',
    'dk.create_container': 'コンテナを作成', 'dk.refresh': '更新', 'dk.no_containers': 'コンテナなし',
    'dk.col_name': '名前', 'dk.col_image': 'イメージ', 'dk.col_status': '状態', 'dk.col_ports': 'ポート', 'dk.col_actions': '操作',
    'dk.builtin': '内蔵', 'dk.stop': '停止', 'dk.restart': '再起動', 'dk.terminal': 'ターミナル', 'dk.files': 'ファイル', 'dk.start': '起動', 'dk.logs': 'ログ', 'dk.networks': 'ネットワーク', 'dk.delete': '削除',
    'dk.ctn_term': 'コンテナターミナル · ', 'dk.ctn_files': 'コンテナファイル · ',
    'dk.confirm_rm_ctn': 'コンテナ {name} を削除しますか？', 'dk.op_ok': '操作に成功しました', 'dk.logs_title': 'ログ · ', 'dk.empty_log': '(空)',
    'dk.net_title': 'ネットワーク · ', 'dk.connected': '接続済み', 'dk.disconnect': '切断', 'dk.connectable': '接続可能', 'dk.connect': '接続', 'dk.none': 'なし',
    'dk.image': 'イメージ', 'dk.image_ph': 'イメージを選択または入力（例 nginx:latest）', 'dk.ctn_name': 'コンテナ名（任意）', 'dk.restart_policy': '再起動ポリシー',
    'dk.port_map': 'ポートマッピング', 'dk.add_port': '+ ポートを追加', 'dk.env': '環境変数', 'dk.add_env': '+ 変数を追加', 'dk.volumes': 'ボリューム', 'dk.add_vol': '+ マウントを追加',
    'dk.start_cmd': '起動コマンド（任意）', 'dk.cmd_ph': '空欄ならイメージ既定', 'dk.alloc_tty': 'TTY を割り当て', 'dk.start_after': '作成後に起動',
    'dk.create': '作成', 'dk.need_image': 'イメージを入力してください', 'dk.ctn_created': 'コンテナを作成しました',
    'dk.host_port': 'ホストポート', 'dk.container_port': 'コンテナポート', 'dk.host_path': 'ホストパス /data/app', 'dk.container_path': 'コンテナパス /app', 'dk.readonly': '読み取り専用',
    'dk.create_network': 'ネットワークを作成', 'dk.net_name': 'ネットワーク名', 'dk.col_driver': 'ドライバ', 'dk.col_scope': 'スコープ', 'dk.confirm_rm_net': 'ネットワーク {name} を削除しますか？',
    'dk.no_images': 'イメージなし', 'dk.col_size': 'サイズ', 'dk.col_created': '作成日時', 'dk.pull_image': 'イメージを取得', 'dk.confirm_rm_img': 'イメージ {name} を削除しますか？',
    'dk.img_name_label': 'イメージ名（例 nginx:latest）', 'dk.mirror_label': '高速化ミラー（任意）', 'dk.mirror_none': '使用しない', 'dk.pull_start': '取得開始', 'dk.need_image_name': 'イメージ名を入力してください', 'dk.pull_done': '取得完了',
  },
};

// Short label shown on the switcher button per language.
const LANG_FULL = { en: 'English', 'zh-CN': '简体中文', 'zh-TW': '繁體中文', ja: '日本語' };
// A clean line-art globe icon for the switcher (matches the nav/topbar icons).
const GLOBE_SVG = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.6 2.7 2.6 15.3 0 18M12 3c-2.6 2.7-2.6 15.3 0 18"/></svg>';

function curLang() { return window.__LANG__ || 'en'; }

// Translate a key (with optional {var} substitution); falls back to English,
// then to the key itself.
function tr(key, vars) {
  const d = I18N[curLang()] || I18N.en;
  let s = (d && d[key] != null) ? d[key] : (I18N.en[key] != null ? I18N.en[key] : key);
  if (vars) for (const k in vars) s = s.split('{' + k + '}').join(vars[k]);
  return s;
}

// Translate static nodes: text via data-i18n, placeholder via data-i18n-ph,
// title via data-i18n-title.
function applyI18n(root) {
  const r = root || document;
  r.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = tr(el.getAttribute('data-i18n')); });
  r.querySelectorAll('[data-i18n-ph]').forEach((el) => { el.setAttribute('placeholder', tr(el.getAttribute('data-i18n-ph'))); });
  r.querySelectorAll('[data-i18n-title]').forEach((el) => { el.setAttribute('title', tr(el.getAttribute('data-i18n-title'))); });
}

// Persist a manual language choice and reload so the whole UI re-renders in it.
function setLang(code) {
  if (!I18N[code] || code === curLang()) return;
  try { localStorage.setItem('dn7_lang', code); } catch (e) {}
  location.reload();
}

// Language switcher popup anchored to the topbar button.
function toggleLangMenu() {
  let pop = document.querySelector('.lang-pop');
  if (pop) { pop.remove(); return; }
  const btn = document.getElementById('langBtn');
  if (!btn) return;
  pop = document.createElement('div');
  pop.className = 'selx-pop lang-pop';
  ['en', 'zh-CN', 'zh-TW', 'ja'].forEach((code) => {
    const o = document.createElement('div');
    o.className = 'selx-opt' + (code === curLang() ? ' sel' : '');
    o.textContent = LANG_FULL[code];
    o.addEventListener('mousedown', (e) => { e.preventDefault(); pop.remove(); setLang(code); });
    pop.appendChild(o);
  });
  document.body.appendChild(pop);
  const r = btn.getBoundingClientRect();
  pop.style.minWidth = '120px';
  pop.style.left = Math.max(8, r.right - 120) + 'px';
  pop.style.top = (r.bottom + 4) + 'px';
  const close = (e) => { if (!e.target.closest('.lang-pop') && e.target.id !== 'langBtn') { pop.remove(); document.removeEventListener('mousedown', close, true); } };
  setTimeout(() => document.addEventListener('mousedown', close, true), 0);
}

// Initialize: translate the static DOM, label the switcher, then reveal.
(function initI18n() {
  applyI18n(document);
  const btn = document.getElementById('langBtn');
  if (btn) {
    btn.innerHTML = GLOBE_SVG;
    btn.title = tr('lang.name') + ' · ' + (LANG_FULL[curLang()] || '');
    btn.onclick = toggleLangMenu;
  }
  document.documentElement.setAttribute('data-i18n-ready', '1');
})();
