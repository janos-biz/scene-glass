{
  "targets": [
    {
      "target_name": "secure_read",
      "sources": [],
      "defines": ["NAPI_VERSION=9"],
      "conditions": [
        [
          "OS=='mac'",
          {
            "sources": ["native/secure_read.cc"],
            "xcode_settings": {
              "CLANG_CXX_LANGUAGE_STANDARD": "c++20",
              "CLANG_CXX_LIBRARY": "libc++",
              "GCC_ENABLE_CPP_EXCEPTIONS": "NO",
              "OTHER_CPLUSPLUSFLAGS": ["-fno-exceptions"]
            }
          }
        ],
        [
          "OS=='linux'",
          {
            "sources": ["native/secure_read.cc"],
            "cflags_cc": ["-std=c++20", "-fno-exceptions"]
          }
        ],
        [
          "OS!='mac' and OS!='linux'",
          {
            "type": "none"
          }
        ]
      ]
    }
  ]
}
