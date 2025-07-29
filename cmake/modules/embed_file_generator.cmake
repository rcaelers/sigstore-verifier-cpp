file(READ "${INPUT_FILE}" FILE_CONTENT)

string(CONCAT HEADER_CONTENT
    "// Auto-generated file containing embedded ${INPUT_FILENAME}\n"
    "// Do not modify this file manually\n"
    "\n"
    "#pragma once\n"
    "#include <string_view>\n"
    "\n"
    "namespace {\n"
    "\n"
    "constexpr std::string_view ${VARIABLE_NAME}(R\"EMBED_DELIMITER(\n"
    "${FILE_CONTENT}"
    ")EMBED_DELIMITER\");\n"
    "\n"
    "constexpr size_t ${VARIABLE_NAME}_size = ${VARIABLE_NAME}.size();\n"
    "\n"
    "} // namespace\n"
)

file(WRITE "${OUTPUT_FILE}" "${HEADER_CONTENT}")
