#include "rpc_contract.h"

int main() {
  if (disconnectRequest({}).has_value()) return 1;
  if (disconnectRequest({{"vpn", QJsonObject{{"connected", true}}}}).has_value()) return 2;
  if (disconnectRequest({{"vpn", QJsonObject{{"connected", false}, {"connection_id", "old"}}}}).has_value()) return 3;
  const auto body = disconnectRequest({{"vpn", QJsonObject{{"connected", true}, {"connection_id", "active"}, {"peer_id", "not-the-connection"}}}});
  if (!body || body->value("connection_id").toString() != "active" || body->value("reason").toString() != "user_request" || body->size() != 2) return 4;
  return 0;
}
