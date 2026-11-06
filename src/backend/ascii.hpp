#pragma once

namespace smithproxy::gui {

constexpr bool ascii_lower(const unsigned char character) {
    return character >= static_cast<unsigned char>('a') &&
           character <= static_cast<unsigned char>('z');
}

constexpr bool ascii_upper(const unsigned char character) {
    return character >= static_cast<unsigned char>('A') &&
           character <= static_cast<unsigned char>('Z');
}

constexpr bool ascii_digit(const unsigned char character) {
    return character >= static_cast<unsigned char>('0') &&
           character <= static_cast<unsigned char>('9');
}

constexpr bool ascii_letter(const unsigned char character) {
    return ascii_lower(character) || ascii_upper(character);
}

constexpr bool ascii_alphanumeric(const unsigned char character) {
    return ascii_letter(character) || ascii_digit(character);
}

}  // namespace smithproxy::gui
