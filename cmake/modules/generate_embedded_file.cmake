function(embed_file_as_string_view INPUT_FILE VARIABLE_NAME)
    set(TARGET_NAME "generate_${VARIABLE_NAME}")
    set(OUTPUT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/${VARIABLE_NAME}.h")

    get_filename_component(INPUT_FILE_ABS "${INPUT_FILE}" ABSOLUTE)
    get_filename_component(OUTPUT_HEADER_ABS "${OUTPUT_HEADER}" ABSOLUTE)
    get_filename_component(OUTPUT_DIR "${OUTPUT_HEADER_ABS}" DIRECTORY)
    get_filename_component(INPUT_FILENAME "${INPUT_FILE_ABS}" NAME)

    add_custom_command(
        OUTPUT "${OUTPUT_HEADER_ABS}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}"
        COMMAND ${CMAKE_COMMAND}
            -DINPUT_FILE=${INPUT_FILE_ABS}
            -DOUTPUT_FILE=${OUTPUT_HEADER_ABS}
            -DVARIABLE_NAME=${VARIABLE_NAME}
            -DINPUT_FILENAME=${INPUT_FILENAME}
            -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/embed_file_generator.cmake"
        DEPENDS "${INPUT_FILE_ABS}"
        COMMENT "Generating embedded file header: ${VARIABLE_NAME} from ${INPUT_FILE}"
        VERBATIM
    )

    add_custom_target(${TARGET_NAME}
        DEPENDS "${INPUT_FILE_ABS}"
        COMMENT "Embedded file target: ${VARIABLE_NAME} from ${INPUT_FILE}")

    set(${VARIABLE_NAME}_TARGET ${TARGET_NAME} PARENT_SCOPE)
    set(${VARIABLE_NAME}_HEADER "${OUTPUT_HEADER_ABS}" PARENT_SCOPE)
    message(STATUS "Created embedded file target: ${TARGET_NAME} -> ${OUTPUT_HEADER}")
endfunction()
