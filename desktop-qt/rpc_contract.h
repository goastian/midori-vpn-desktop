#pragma once

#include <QJsonObject>
#include <QString>
#include <optional>

inline std::optional<QJsonObject> disconnectRequest(const QJsonObject &snapshot) {
  const QJsonObject vpn = snapshot.value(QStringLiteral("vpn")).toObject();
  const QString id = vpn.value(QStringLiteral("connection_id")).toString();
  if (!vpn.value(QStringLiteral("connected")).toBool(false) || id.isEmpty()) return std::nullopt;
  return QJsonObject{{QStringLiteral("connection_id"), id}, {QStringLiteral("reason"), QStringLiteral("user_request")}};
}
