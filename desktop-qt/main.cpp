#include <QApplication>
#include <QCommandLineParser>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMenu>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QSystemTrayIcon>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>

class DesktopController final : public QObject {
  Q_OBJECT
  Q_PROPERTY(QString statusText READ statusText NOTIFY statusChanged)
  Q_PROPERTY(bool connected READ connected NOTIFY statusChanged)
  Q_PROPERTY(bool authenticated READ authenticated NOTIFY statusChanged)
  Q_PROPERTY(bool meshActive READ meshActive NOTIFY statusChanged)
  Q_PROPERTY(QVariantList servers READ servers NOTIFY serversChanged)
  Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorChanged)
  Q_PROPERTY(bool trayAvailable READ trayAvailable CONSTANT)
  Q_PROPERTY(bool startMinimized READ startMinimized NOTIFY settingsChanged)
  Q_PROPERTY(bool autostartEnabled READ autostartEnabled NOTIFY settingsChanged)

public:
  DesktopController(QApplication &application, QString agentPath, int port, QString uiDir, bool autostart)
      : app(application), agentPath(std::move(agentPath)), port(port), uiDir(std::move(uiDir)), launchedByAutostart(autostart) {
    poll.setInterval(3000);
    connect(&poll, &QTimer::timeout, this, &DesktopController::refreshStatus);

    tray.setIcon(QIcon::fromTheme(QStringLiteral("network-vpn"), QIcon(QStringLiteral("/usr/share/icons/hicolor/128x128/apps/midorivpn.png"))));
    tray.setToolTip(QStringLiteral("MidoriVPN"));
    tray.setContextMenu(&trayMenu);
    connect(&tray, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
      if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) openDashboard();
    });
    auto *openAction = trayMenu.addAction(QStringLiteral("Abrir panel MidoriVPN"));
    connect(openAction, &QAction::triggered, this, &DesktopController::openDashboard);
    disconnectAction = trayMenu.addAction(QStringLiteral("Desconectar"));
    connect(disconnectAction, &QAction::triggered, this, &DesktopController::disconnectVPN);
    serverMenu = trayMenu.addMenu(QStringLiteral("Conectar a servidor"));
    trayMenu.addSeparator();
    auto *quitAction = trayMenu.addAction(QStringLiteral("Salir y desconectar"));
    connect(quitAction, &QAction::triggered, this, &DesktopController::shutdown);
    connect(&trayMenu, &QMenu::aboutToShow, this, &DesktopController::refreshTray);
    // The browser dashboard can request /app/quit directly from the child
    // agent. Keep the shell and agent as one lifecycle: once the owned agent
    // exits (cleanly or fatally), remove the tray instead of leaving an
    // orphaned desktop process behind.
    connect(&agent, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
      poll.stop();
      tray.hide();
      QTimer::singleShot(0, &app, &QCoreApplication::quit);
    });
  }

  void start() { startAgent(); waitForAgent(); }
  QString statusText() const { return status; }
  bool connected() const { return isConnected; }
  bool authenticated() const { return isAuthenticated; }
  bool meshActive() const { return isMeshActive; }
  QVariantList servers() const { return serverList; }
  QString errorMessage() const { return error; }
  bool trayAvailable() const { return QSystemTrayIcon::isSystemTrayAvailable(); }
  bool startMinimized() const { return minimized; }
  bool autostartEnabled() const { return autostartEnabledValue; }

  Q_INVOKABLE void login() {
    request("POST", QStringLiteral("oauth/start"), QJsonObject{}, [this](const QJsonObject &response) {
      const QUrl url(response.value(QStringLiteral("url")).toString());
      if (!url.isValid() || url.scheme() != QStringLiteral("https")) return setError(QStringLiteral("No se pudo iniciar el acceso seguro."));
      QDesktopServices::openUrl(url);
    });
  }
  Q_INVOKABLE void connectToServer(const QString &id, const QString &protocol) {
    if (id.isEmpty()) return;
    request("POST", QStringLiteral("vpn/connect"), QJsonObject{{QStringLiteral("server_id"), id}, {QStringLiteral("protocol"), protocol}});
  }
  Q_INVOKABLE void disconnectVPN() { request("POST", QStringLiteral("vpn/disconnect"), QJsonObject{}); }
  Q_INVOKABLE void toggleMesh() { request("POST", isMeshActive ? QStringLiteral("mesh/disable") : QStringLiteral("mesh/enable"), QJsonObject{}); }
  Q_INVOKABLE void setStartMinimized(bool value) {
    request("POST", QStringLiteral("settings"), QJsonObject{{QStringLiteral("mesh"), QJsonObject{{QStringLiteral("start_disabled"), meshStartDisabled}}}, {QStringLiteral("autostart"), QJsonObject{{QStringLiteral("enabled"), autostartEnabledValue}}}, {QStringLiteral("ui"), QJsonObject{{QStringLiteral("start_minimized"), value}}}}, [this, value](const QJsonObject &) {
      minimized = value;
      emit settingsChanged();
    });
  }
  Q_INVOKABLE void setAutostart(bool value) {
    request("POST", QStringLiteral("system/autostart"), QJsonObject{{QStringLiteral("enabled"), value}}, [this, value](const QJsonObject &) {
      autostartEnabledValue = value;
      emit settingsChanged();
    });
  }
  Q_INVOKABLE void grantPermissions() { request("POST", QStringLiteral("system/capabilities"), QJsonObject{{QStringLiteral("extended"), false}}); }
  void openDashboard() {
    // Do not open the loopback root directly: the Vue browser shell requires
    // the per-session token in a URL fragment. The agent's --open-ui path
    // creates a mode-0600 redirect file and supplies that token without ever
    // placing it in process arguments, logs, or a network request.
    if (!QProcess::startDetached(agentPath, {QStringLiteral("--port"), QString::number(port), QStringLiteral("--ui-dir"), uiDir, QStringLiteral("--open-ui")})) {
      setError(QStringLiteral("No se pudo abrir el panel local de MidoriVPN."));
    }
  }
  Q_INVOKABLE void shutdown() {
    if (stopping) return;
    stopping = true;
    poll.stop();
    request("POST", QStringLiteral("vpn/disconnect"), QJsonObject{});
    request("POST", QStringLiteral("app/quit"), QJsonObject{});
    QTimer::singleShot(3000, &app, &QCoreApplication::quit);
  }

signals:
  void statusChanged();
  void serversChanged();
  void errorChanged();
  void settingsChanged();

private:
  QApplication &app;
  QString agentPath, uiDir, token, status = QStringLiteral("Iniciando agente local…"), error;
  int port;
  bool launchedByAutostart, initialized = false, stopping = false, isConnected = false, isAuthenticated = false, isMeshActive = false;
  bool minimized = false, autostartEnabledValue = false, meshStartDisabled = false;
  QVariantList serverList;
  QProcess agent;
  QNetworkAccessManager network;
  QTimer poll;
  QSystemTrayIcon tray;
  QMenu trayMenu;
  QMenu *serverMenu = nullptr;
  QAction *disconnectAction = nullptr;

  QUrl endpoint(const QString &path) const { return QUrl(QStringLiteral("http://127.0.0.1:%1/%2").arg(port).arg(path)); }
  QString tokenPath() const { return QDir(qEnvironmentVariable("XDG_RUNTIME_DIR")).filePath(QStringLiteral("midorivpn-agent.token")); }
  void setError(const QString &value) { error = value; emit errorChanged(); }

  bool readToken() {
    QFileInfo info(tokenPath());
    if (!info.exists() || !info.isFile() || !info.permission(QFile::ReadOwner) || info.permission(QFile::ReadGroup) || info.permission(QFile::ReadOther)) return false;
    QFile file(tokenPath());
    if (!file.open(QIODevice::ReadOnly)) return false;
    token = QString::fromUtf8(file.readAll()).trimmed();
    return token.size() >= 32;
  }
  bool rpcReady() const {
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, port);
    const bool ready = socket.waitForConnected(80);
    socket.abort();
    return ready;
  }
  void startAgent() {
    agent.setProgram(agentPath);
    agent.setArguments({QStringLiteral("--port"), QString::number(port), QStringLiteral("--ui-dir"), uiDir,
                        launchedByAutostart ? QStringLiteral("--background") : QStringLiteral("--open-ui")});
    agent.setProcessChannelMode(QProcess::ForwardedErrorChannel);
    agent.start();
  }
  void waitForAgent(int attempts = 0) {
    if (rpcReady() && readToken()) return initialise();
    if (attempts >= 100) return setError(QStringLiteral("No se pudo iniciar el agente local de MidoriVPN."));
    QTimer::singleShot(100, this, [this, attempts] { waitForAgent(attempts + 1); });
  }
  void initialise() {
    if (initialized) return;
    initialized = true;
    poll.start();
    refreshStatus();
    request("GET", QStringLiteral("settings"), QJsonObject{}, [this](const QJsonObject &settings) {
      const QJsonObject ui = settings.value(QStringLiteral("ui")).toObject();
      const QJsonObject mesh = settings.value(QStringLiteral("mesh")).toObject();
      minimized = ui.value(QStringLiteral("start_minimized")).toBool(false);
      meshStartDisabled = mesh.value(QStringLiteral("start_disabled")).toBool(false);
      emit settingsChanged();
      request("GET", QStringLiteral("system/autostart"), QJsonObject{}, [this](const QJsonObject &value) {
        autostartEnabledValue = value.value(QStringLiteral("enabled")).toBool(false);
        emit settingsChanged();
        if (trayAvailable()) tray.show();
        refreshTray();
        // A normal launch reaches the proven agent --open-ui path above. It
        // creates the protected redirect and hands Vue its ephemeral session
        // token before the dashboard is loaded. Autostart remains background
        // only when the user asked to start minimized and a tray exists.
        if (launchedByAutostart && !(minimized && trayAvailable())) openDashboard();
      });
    });
  }
  void request(const QString &method, const QString &path, const QJsonObject &body, std::function<void(const QJsonObject &)> callback = {}) {
    if (token.isEmpty()) return;
    QNetworkRequest request(endpoint(path));
    request.setRawHeader("X-Agent-Token", token.toUtf8());
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    QNetworkReply *reply = method == QStringLiteral("GET") ? network.get(request) : network.sendCustomRequest(request, method.toUtf8(), QJsonDocument(body).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply, callback = std::move(callback)] {
      const QByteArray data = reply->readAll();
      const bool ok = reply->error() == QNetworkReply::NoError;
      reply->deleteLater();
      if (!ok) return setError(QStringLiteral("La operación local no pudo completarse."));
      if (callback) callback(QJsonDocument::fromJson(data).object());
    });
  }
  void refreshStatus() {
    request("GET", QStringLiteral("status"), QJsonObject{}, [this](const QJsonObject &snapshot) {
      const QJsonObject vpn = snapshot.value(QStringLiteral("vpn")).toObject();
      const QJsonObject auth = snapshot.value(QStringLiteral("auth")).toObject();
      const QJsonObject mesh = snapshot.value(QStringLiteral("mesh")).toObject();
      isConnected = vpn.value(QStringLiteral("connected")).toBool(false);
      isAuthenticated = auth.value(QStringLiteral("logged_in")).toBool(false);
      isMeshActive = mesh.value(QStringLiteral("active")).toBool(false);
      const QString server = vpn.value(QStringLiteral("server_name")).toString();
      status = isConnected ? QStringLiteral("Conectado a %1").arg(server) : QStringLiteral("Desconectado");
      tray.setToolTip(QStringLiteral("MidoriVPN — %1").arg(status));
      disconnectAction->setEnabled(isConnected);
      emit statusChanged();
    });
  }
  void refreshTray() {
    refreshStatus();
    serverMenu->clear();
    QNetworkRequest request(endpoint(QStringLiteral("servers")));
    request.setRawHeader("X-Agent-Token", token.toUtf8());
    QNetworkReply *reply = network.get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
      const QByteArray data = reply->readAll();
      const bool ok = reply->error() == QNetworkReply::NoError;
      reply->deleteLater();
      serverList.clear();
      const QJsonArray servers = QJsonDocument::fromJson(data).array();
      for (const QJsonValue &entry : servers) {
        const QJsonObject item = entry.toObject();
        if (!item.value(QStringLiteral("is_active")).toBool(true)) continue;
        const QString id = item.value(QStringLiteral("id")).toString();
        const QString name = item.value(QStringLiteral("name")).toString();
        if (id.isEmpty() || name.isEmpty()) continue;
        serverList.append(QVariantMap{{QStringLiteral("id"), id}, {QStringLiteral("name"), name}, {QStringLiteral("location"), item.value(QStringLiteral("location")).toString()}});
        QAction *action = serverMenu->addAction(name);
        connect(action, &QAction::triggered, this, [this, id] { connectToServer(id, QStringLiteral("smart_auto")); });
      }
      if (!ok || serverMenu->actions().isEmpty()) { auto *empty = serverMenu->addAction(QStringLiteral("No hay servidores disponibles")); empty->setEnabled(false); }
      emit serversChanged();
    });
  }
};

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);
  QCoreApplication::setApplicationName(QStringLiteral("MidoriVPN"));
  QCommandLineParser parser;
  parser.addHelpOption();
  parser.addOption({QStringLiteral("agent"), QStringLiteral("Path to the MidoriVPN agent."), QStringLiteral("path"), QStringLiteral("/usr/libexec/midorivpn-agent")});
  parser.addOption({QStringLiteral("port"), QStringLiteral("Local agent RPC port."), QStringLiteral("port"), QStringLiteral("7071")});
  parser.addOption({QStringLiteral("ui-dir"), QStringLiteral("Installed Vue UI directory."), QStringLiteral("path"), QStringLiteral("/usr/share/midorivpn/ui")});
  parser.addOption({QStringLiteral("autostart"), QStringLiteral("Launch as an XDG autostart application.")});
  parser.process(app);
  bool validPort = false;
  const int port = parser.value(QStringLiteral("port")).toInt(&validPort);
  if (!validPort || port < 1024 || port > 65535) return 2;

  DesktopController controller(app, parser.value(QStringLiteral("agent")), port, parser.value(QStringLiteral("ui-dir")), parser.isSet(QStringLiteral("autostart")));
  controller.start();
  return app.exec();
}

#include "main.moc"
