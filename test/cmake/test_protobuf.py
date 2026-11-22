"""Configure-only checks for target Protobuf and native protoc selection."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


MODULE = Path(__file__).resolve().parents[2] / "cmake/modules/SigstoreProtobuf.cmake"


@unittest.skipUnless(os.name != "nt" and shutil.which("cmake"), "POSIX executable fixtures and CMake required")
class ProtobufConfigureTest(unittest.TestCase):
    def configure(self, *, cross=True, version="36.2.0", host_version="36.2",
                  explicit=True, runnable=True, fallback=False, redirect=False, overwrite_tool=False):
        with tempfile.TemporaryDirectory(prefix="sigstore host protoc ") as directory:
            root = Path(directory)
            host = root / "host/bin"
            host.mkdir(parents=True)
            protoc = host / "protoc"
            protoc.write_text("#!" + sys.executable + "\n"
                              + (f'print("libprotoc {host_version}")\n' if runnable else "raise SystemExit(42)\n"))
            protoc.chmod(0o755)
            target = root / "target/bin"
            target.mkdir(parents=True)
            (target / "protoc").write_text("#!/bin/sh\nexit 99\n")
            (target / "protoc").chmod(0o755)

            sources = root / "protobuf"
            (sources / "cmake").mkdir(parents=True)
            (sources / "cmake/protobuf-generate.cmake").write_text("function(protobuf_generate)\nendfunction()\n")
            (sources / "CMakeLists.txt").write_text('''
cmake_minimum_required(VERSION 3.23)
project(protobuf NONE)
if(protobuf_BUILD_TESTS OR NOT protobuf_BUILD_SHARED_LIBS OR protobuf_BUILD_PROTOC_BINARIES)
  message(FATAL_ERROR "Wrong target Protobuf build options")
endif()
''')
            config = root / "config"
            config.mkdir()
            (config / "ProtobufConfig.cmake").write_text(
                f'set(Protobuf_VERSION "{version}")\n'
                + (f'set(Protobuf_PROTOC_EXECUTABLE "{target / "protoc"}")\n' if overwrite_tool else "")
                + (f'set(protobuf_SOURCE_DIR "{sources}")\n' if redirect else "function(protobuf_generate)\nendfunction()\n"))
            setup = f'set(CMAKE_CROSSCOMPILING {"TRUE" if cross else "FALSE"})\n'
            setup += f'set(CMAKE_PREFIX_PATH "{root / "target"}")\n'
            if fallback:
                setup += 'set(CMAKE_DISABLE_FIND_PACKAGE_Protobuf TRUE)\n'
                setup += f'set(FETCHCONTENT_SOURCE_DIR_PROTOBUF "{sources}")\n'
            else:
                setup += f'set(Protobuf_DIR "{config}")\n'
            if explicit:
                setup += f'set(Protobuf_PROTOC_EXECUTABLE "{protoc}" CACHE FILEPATH "")\n'
            (root / "CMakeLists.txt").write_text('''
cmake_minimum_required(VERSION 3.23)
project(protobuf_selection NONE)
include(FetchContent)
''' + setup + f'include("{MODULE}")\n'
                + 'if(NOT COMMAND protobuf_generate)\nmessage(FATAL_ERROR "Missing generator")\nendif()\n'
                + 'file(WRITE "${CMAKE_BINARY_DIR}/selected" "${SIGSTORE_PROTOC_ARGS}")\n')
            env = dict(os.environ, PATH=str(host) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["cmake", "-S", str(root), "-B", str(root / "build")],
                                    env=env, text=True, capture_output=True)
            selected = root / "build/selected"
            return result.returncode, result.stdout + result.stderr, selected.read_text() if selected.exists() else ""

    def test_cross_build_uses_host_path_not_target_prefix(self):
        code, output, selected = self.configure(explicit=False)
        self.assertEqual(code, 0, output)
        self.assertIn("PROTOC_EXE;", selected)
        self.assertIn("/host/bin/protoc", selected)

    def test_target_config_cannot_replace_selected_host_tool(self):
        code, output, selected = self.configure(overwrite_tool=True)
        self.assertEqual(code, 0, output)
        self.assertIn("/host/bin/protoc", selected)

    def test_explicit_tool_supports_cpp_package_version(self):
        code, output, _ = self.configure(version="7.36.2")
        self.assertEqual(code, 0, output)

    def test_target_sources_keep_cross_build_options(self):
        code, output, selected = self.configure(fallback=True)
        self.assertEqual(code, 0, output)
        self.assertIn("PROTOC_EXE;", selected)

    def test_package_redirect_loads_generator_helper(self):
        code, output, _ = self.configure(redirect=True)
        self.assertEqual(code, 0, output)

    def test_native_build_keeps_target_generator_default(self):
        code, output, selected = self.configure(cross=False, explicit=False)
        self.assertEqual(code, 0, output)
        self.assertEqual(selected, "")

    def test_wrong_host_version_is_rejected(self):
        code, output, _ = self.configure(host_version="35.1")
        self.assertNotEqual(code, 0)
        self.assertIn("does not match target Protobuf 36.2", output)

    def test_target_executable_is_rejected(self):
        code, output, _ = self.configure(runnable=False)
        self.assertNotEqual(code, 0)
        self.assertIn("must run on the build host", output)


if __name__ == "__main__":
    unittest.main()
