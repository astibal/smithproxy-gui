#pragma once

#include "config.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

// Creates a persistent scrypt verifier without retaining the supplied password.
std::optional<GuiAdministratorConfig> create_password_verifier(
    std::string administrator, std::string_view password);

// Performs the same bounded derivation and compares the verifier in constant time.
bool verify_password(const GuiAdministratorConfig& administrator, std::string_view password);

} // namespace smithproxy::gui
