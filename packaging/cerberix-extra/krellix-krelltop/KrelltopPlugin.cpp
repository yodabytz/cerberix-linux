#include "KrelltopPlugin.h"

#include "remote/RemoteSource.h"
#include "widgets/Decal.h"
#include "widgets/Panel.h"

#include <QProcess>
#include <QRegularExpression>
#include <QSettings>
#include <QStringList>
#include <QTcpSocket>
#include <QTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <cmath>

#include <algorithm>

namespace {

constexpr int kVisibleRows = 3;
constexpr int kTooltipRows = 6;

QString pct(double value)
{
    return QString::number(value, 'f', value >= 10.0 ? 0 : 1) + QLatin1Char('%');
}

QString elideMiddle(const QString &value, int maxChars)
{
    if (value.size() <= maxChars)
        return value;
    if (maxChars <= 3)
        return value.left(maxChars);
    const int left = (maxChars - 1) / 2;
    const int right = maxChars - left - 1;
    return value.left(left) + QStringLiteral("...") + value.right(right);
}

QList<KrelltopMonitor::ProcessRow> topRows(QList<KrelltopMonitor::ProcessRow> rows,
                                           bool byMemory)
{
    std::sort(rows.begin(), rows.end(), [byMemory](const auto &a, const auto &b) {
        if (byMemory) {
            if (a.rssKiB != b.rssKiB)
                return a.rssKiB > b.rssKiB;
            return a.mem > b.mem;
        }
        if (a.cpu != b.cpu)
            return a.cpu > b.cpu;
        return a.rssKiB > b.rssKiB;
    });
    return rows.mid(0, kTooltipRows);
}

QString tooltipSection(const QString &title, const QList<KrelltopMonitor::ProcessRow> &rows, bool memory)
{
    QStringList lines;
    lines << title;
    const int limit = qMin(kTooltipRows, rows.size());
    for (int i = 0; i < limit; ++i) {
        const auto &row = rows.at(i);
        lines << QStringLiteral("%1. %2  pid %3  cpu %4  mem %5 (%6)")
                     .arg(i + 1)
                     .arg(KrelltopMonitor::displayNameFor(row))
                     .arg(row.pid)
                     .arg(pct(row.cpu))
                     .arg(pct(row.mem))
                     .arg(KrelltopMonitor::formatRss(row.rssKiB));
        if (!row.command.isEmpty())
            lines << QStringLiteral("   %1").arg(elideMiddle(row.command, memory ? 120 : 100));
    }
    if (limit == 0)
        lines << QStringLiteral("No process data.");
    return lines.join(QLatin1Char('\n'));
}

QList<KrelltopMonitor::ProcessRow> remoteRows(const QJsonArray &remote)
{
    QList<KrelltopMonitor::ProcessRow> rows;
    for (const QJsonValue &value : remote) {
        const QJsonObject src = value.toObject();
        KrelltopMonitor::ProcessRow row;
        row.pid = src.value(QStringLiteral("pid")).toInt();
        row.cpu = src.value(QStringLiteral("cpu")).toDouble();
        row.mem = src.value(QStringLiteral("mem")).toDouble();
        row.rssKiB = src.value(QStringLiteral("rss")).toInteger();
        row.name = src.value(QStringLiteral("name")).toString();
        row.command = src.value(QStringLiteral("cmd")).toString();
        if (row.pid > 0 && !row.name.isEmpty() && std::isfinite(row.cpu) && std::isfinite(row.mem))
            rows.append(row);
    }
    return rows;
}

} // namespace

KrelltopMonitor::KrelltopMonitor(Theme *theme, QObject *parent)
    : MonitorBase(theme, parent)
{
}

QWidget *KrelltopMonitor::createWidget(QWidget *parent)
{
    auto *panel = new Panel(theme(), parent);
    panel->setSurfaceKey(QStringLiteral("panel_bg_krelltop"));
    panel->setTitle(QStringLiteral("Top"));
    m_panel = panel;

    for (int i = 0; i < kVisibleRows; ++i) {
        auto *row = panel->addDecal(i == 0 ? QStringLiteral("value") : QStringLiteral("label"),
                                    i == 0 ? QStringLiteral("text_primary") : QStringLiteral("text_secondary"));
        row->setAlignment(Qt::AlignHCenter);
        m_rows << row;
    }

    tick();
    return panel;
}

void KrelltopMonitor::tick()
{
    if (RemoteSource *remote = RemoteSource::instance()) {
        if (remote->isConnected())
            fetchRemote(remote->remoteAddress());
        else {
            if (m_timeout) m_timeout->stop();
            if (m_socket) m_socket->abort();
            setUnavailable(QStringLiteral("remote disconnected"));
        }
        return;
    }

    QString error;
    const QList<ProcessRow> processes = readProcesses(&error);
    if (!error.isEmpty()) {
        setUnavailable(error);
        return;
    }

    setRows(topRows(processes, false), topRows(processes, true));
}

void KrelltopMonitor::fetchRemote(const QString &address)
{
    // Use the wire protocol, never an inline accessor into the host's private layout.
    if (!m_socket) {
        m_socket = new QTcpSocket(this);
        m_socket->setReadBufferSize(1024 * 1024 + 1);
        m_timeout = new QTimer(this);
        m_timeout->setSingleShot(true);
        connect(m_timeout, &QTimer::timeout, this, [this] {
            m_socket->abort();
            setUnavailable(QStringLiteral("remote process request timed out"));
        });
        connect(m_socket, &QTcpSocket::errorOccurred, this, [this] {
            m_timeout->stop();
            setUnavailable(QStringLiteral("remote process connection unavailable"));
        });
        connect(m_socket, &QTcpSocket::readyRead, this, [this] {
            m_buffer += m_socket->readAll();
            if (m_buffer.size() > 1024 * 1024) {
                m_timeout->stop();
                m_socket->abort();
                m_buffer.clear();
                setUnavailable(QStringLiteral("remote process message too large"));
                return;
            }
            qsizetype newline;
            while ((newline = m_buffer.indexOf('\n')) >= 0) {
                const auto doc = QJsonDocument::fromJson(m_buffer.left(newline));
                m_buffer.remove(0, newline + 1);
                const auto object = doc.object();
                if (object.value(QStringLiteral("type")).toString() != QStringLiteral("sample"))
                    continue;
                const auto rows = remoteRows(object.value(QStringLiteral("top")).toArray());
                m_timeout->stop();
                m_socket->abort();
                m_buffer.clear();
                if (rows.isEmpty())
                    setUnavailable(QStringLiteral("server provides no process data"));
                else
                    setRows(topRows(rows, false), topRows(rows, true));
                return;
            }
        });
    }
    if (m_socket->state() != QAbstractSocket::UnconnectedState)
        return;
    const auto colon = address.lastIndexOf(QLatin1Char(':'));
    bool validPort = false;
    const uint port = address.mid(colon + 1).toUInt(&validPort);
    if (colon < 1 || !validPort || port == 0 || port > 65535) {
        setUnavailable(QStringLiteral("invalid remote address"));
        return;
    }
    QString host = address.left(colon);
    if (host.startsWith(QLatin1Char('[')) && host.endsWith(QLatin1Char(']')))
        host = host.mid(1, host.size() - 2);
    m_buffer.clear();
    m_timeout->start(4000);
    m_socket->connectToHost(host, static_cast<quint16>(port));
}

QList<KrelltopMonitor::ProcessRow> KrelltopMonitor::readProcesses(QString *error)
{
    QProcess proc;
    proc.setProgram(QStringLiteral("ps"));
    proc.setArguments({QStringLiteral("-eo"),
                       QStringLiteral("pid=,pcpu=,pmem=,rss=,comm=,args="),
                       QStringLiteral("--sort=-pcpu")});
    proc.setProcessChannelMode(QProcess::MergedChannels);
    proc.start();
    if (!proc.waitForFinished(2000)) {
        proc.kill();
        proc.waitForFinished(300);
        if (error)
            *error = QStringLiteral("ps timed out");
        return {};
    }

    const QString output = QString::fromLocal8Bit(proc.readAll());
    if (proc.exitCode() != 0) {
        if (error)
            *error = output.trimmed().isEmpty() ? QStringLiteral("ps failed") : output.trimmed().left(120);
        return {};
    }

    QList<ProcessRow> rows;
    const QRegularExpression rx(QStringLiteral("^\\s*(\\d+)\\s+([0-9.]+)\\s+([0-9.]+)\\s+(\\d+)\\s+(\\S+)\\s*(.*)$"));
    for (const QString &line : output.split(QLatin1Char('\n'))) {
        const QRegularExpressionMatch m = rx.match(line);
        if (!m.hasMatch())
            continue;
        ProcessRow row;
        row.pid = m.captured(1).toInt();
        row.cpu = m.captured(2).toDouble();
        row.mem = m.captured(3).toDouble();
        row.rssKiB = m.captured(4).toLongLong();
        row.name = m.captured(5).trimmed();
        row.command = m.captured(6).trimmed();
        if (row.pid <= 0 || row.name.isEmpty())
            continue;
        rows << row;
    }

    if (rows.isEmpty() && error)
        *error = QStringLiteral("no process rows from ps");
    return rows;
}

QString KrelltopMonitor::formatRss(qint64 rssKiB)
{
    if (rssKiB >= 1024 * 1024)
        return QStringLiteral("%1 GiB").arg(double(rssKiB) / (1024.0 * 1024.0), 0, 'f', 1);
    if (rssKiB >= 1024)
        return QStringLiteral("%1 MiB").arg(double(rssKiB) / 1024.0, 0, 'f', 0);
    return QStringLiteral("%1 KiB").arg(rssKiB);
}

QString KrelltopMonitor::displayNameFor(const ProcessRow &row)
{
    QString name = row.name;
    if (name.startsWith(QLatin1Char('[')) && name.endsWith(QLatin1Char(']')))
        return name;
    if (name.size() > 22)
        name = name.left(19) + QStringLiteral("...");
    return name;
}

void KrelltopMonitor::setRows(const QList<ProcessRow> &byCpu, const QList<ProcessRow> &byMem)
{
    for (int i = 0; i < m_rows.size(); ++i) {
        if (!m_rows.at(i))
            continue;
        if (i >= byCpu.size()) {
            m_rows.at(i)->setText(QStringLiteral("no process"));
            continue;
        }
        const ProcessRow &row = byCpu.at(i);
        m_rows.at(i)->setText(QStringLiteral("%1 %2 %3")
            .arg(i + 1)
            .arg(elideMiddle(displayNameFor(row), 13))
            .arg(pct(row.cpu)));
    }

    QStringList tooltip;
    tooltip << QStringLiteral("KrellTop process usage")
            << tooltipSection(QStringLiteral("Top CPU"), byCpu, false)
            << tooltipSection(QStringLiteral("Top memory"), byMem, true);
    if (m_panel)
        m_panel->setToolTip(tooltip.join(QStringLiteral("\n\n")));
}

void KrelltopMonitor::setUnavailable(const QString &message)
{
    for (int i = 0; i < m_rows.size(); ++i) {
        if (!m_rows.at(i))
            continue;
        m_rows.at(i)->setText(i == 0 ? QStringLiteral("top unavailable")
                                     : (i == 1 ? message.left(32) : QString()));
    }
    if (m_panel)
        m_panel->setToolTip(QStringLiteral("KrellTop\n%1").arg(message));
}

QList<MonitorBase *> KrelltopPlugin::createMonitors(Theme *theme, QObject *parent)
{
    if (!QSettings().value(QStringLiteral("plugins/krelltop/enabled"), false).toBool())
        return {};
    return {new KrelltopMonitor(theme, parent)};
}
