import ObjC from "../vendor/frida-objc-bridge/index.js";

function ResolvePrivateSymbol(moduleName, symbolName) {
  var module = Process.getModuleByName(moduleName);
  var symbols = module.enumerateSymbols();

  for (var i = 0; i < symbols.length; i++) {
    var sym = symbols[i];
    if (sym.name === symbolName) {
      // console.log("[uv] Found symbol: " + sym.name + " at " + sym.address);
      return sym.address.strip();
    }
  }

  console.error("[uv] Symbol not found: " + symbolName);
  return null;
}

function ResolvePrivateSignedSymbol(moduleName, symbolName) {
  var addr = ResolvePrivateSymbol(moduleName, symbolName);
  if (!addr) return null;
  return addr.sign();
}

// const _NSClassFromString = new NativeFunction(
//   Module.getGlobalExportByName("NSClassFromString"),
//   "pointer",
//   ["pointer"],
// );

// function ResolveObjCClassFromString(className) {
//   const nsClassName = ObjC.classes.NSString.stringWithUTF8String_(
//     Memory.allocUtf8String(className),
//   );
//   const klass = _NSClassFromString(nsClassName.handle);

//   if (klass.isNull()) {
//     console.error("[uv] Class not found: " + className);
//     return null;
//   }

//   return new ObjC.Object(klass, undefined, true);
// }

// msin start
//

const _NSGetArgv = new NativeFunction(
  Module.getGlobalExportByName("_NSGetArgv"),
  "pointer",
  [],
);

function getProcessNameFromArgv() {
  const argvPtr = _NSGetArgv().readPointer(); // char **
  const argv0 = argvPtr.readPointer(); // char *
  const fullPath = argv0.readUtf8String(); // e.g. /System/Library/.../Dock

  if (!fullPath) return Process.name;

  const parts = fullPath.split("/");
  return parts[parts.length - 1];
}

const processName = getProcessNameFromArgv();

console.log("[uv] processName:", processName);

const xpc_dictionary_set_string = new NativeFunction(
  ResolvePrivateSignedSymbol(
    "/usr/lib/system/libxpc.dylib",
    "xpc_dictionary_set_string",
  ),
  "void",
  ["pointer", "pointer", "pointer"],
);
const xpc_dictionary_get_string = new NativeFunction(
  ResolvePrivateSignedSymbol(
    "/usr/lib/system/libxpc.dylib",
    "xpc_dictionary_get_string",
  ),
  "pointer",
  ["pointer", "pointer"],
);
const FileAccess = new NativeFunction(
  Module.getGlobalExportByName("access"),
  "int",
  ["pointer", "int"],
);

function WaitForPath(path, timeout = 3, interval = 0.1) {
  const pathPtr = Memory.allocUtf8String(path);
  let waited = 0;
  while (FileAccess(pathPtr, 0) !== 0 && waited < timeout) {
    Thread.sleep(interval);
    waited += interval;
  }
  return FileAccess(pathPtr, 0) === 0;
}

// initproc / codesigning
if (processName === "launchd") {
  const xpc_dictionary_get_value_ptr = ResolvePrivateSignedSymbol(
    "/usr/lib/system/libxpc.dylib",
    "xpc_dictionary_get_value",
  );
  const _xpc_dictionary_get_value_real = new NativeFunction(
    xpc_dictionary_get_value_ptr,
    "pointer",
    ["pointer", "pointer"],
  );
  Interceptor.attach(xpc_dictionary_get_value_ptr, {
    onEnter(args) {
      const xpc_key = args[1].readUtf8String();
      if (xpc_key == "plist") {
        this.real_return_value = _xpc_dictionary_get_value_real(
          args[0],
          args[1],
        );

        const dictionary_string = xpc_dictionary_get_string(
          this.real_return_value,
          Memory.allocUtf8String("Program"),
        ).readUtf8String();

        const match = dictionary_string.match(/([^/]+\.app\/.+)/);
        const appPath = match?.[1];
        this.payloadPath = `/tmp/RuntimeApplications/${appPath}`;

        send({ type: "launch_request", path: dictionary_string });
      }
    },
    onLeave(retval) {
      if (this.payloadPath) {
        if (!WaitForPath(this.payloadPath)) {
          console.log(`[!] timed out waiting for ${this.payloadPath}`);
          return;
        }
        xpc_dictionary_set_string(
          retval,
          Memory.allocUtf8String("Program"),
          Memory.allocUtf8String(this.payloadPath),
        );
      }
    },
  });
  // Interceptor.attach(
  //   ResolvePrivateSignedSymbol(
  //     "/usr/lib/system/libxpc.dylib",
  //     "xpc_data_create_with_dispatch_data",
  //   ),
  //   {
  //     onEnter(args) {
  //       const dispatchData = args[0];

  //       // Allocate output pointers for the mapped buffer and size
  //       const bufPtrOut = Memory.alloc(Process.pointerSize);
  //       const sizePtrOut = Memory.alloc(Process.pointerSize);

  //       // Map the dispatch_data to a contiguous buffer
  //       dispatch_data_create_map(dispatchData, bufPtrOut, sizePtrOut);

  //       const bufPtr = bufPtrOut.readPointer();
  //       const size = sizePtrOut.readUInt();

  //       if (bufPtr.isNull() || size === 0) return;

  //       // Read the raw bytes from the mapped buffer
  //       const bytes = bufPtr.readByteArray(size);
  //       const view = new Uint8Array(bytes);

  //       // Extract null-terminated C strings from the buffer
  //       const strings = [];
  //       let start = 0;

  //       for (let i = 0; i <= view.length; i++) {
  //         const isEnd = i === view.length || view[i] === 0;

  //         if (isEnd) {
  //           if (i > start) {
  //             const slice = view.slice(start, i);
  //             // Filter to only printable ASCII (0x20–0x7E), min length 4
  //             const allPrintable = slice.every((b) => b >= 0x20 && b <= 0x7e);
  //             if (allPrintable && slice.length >= 4) {
  //               strings.push(String.fromCharCode(...slice));
  //             }
  //           }
  //           start = i + 1;
  //         }
  //       }

  //       if (strings.length > 0) {
  //         const path = strings[0];
  //         const argv = [];
  //         const envp = [];
  //         let isEnv = false;

  //         for (let i = 1; i < strings.length; i++) {
  //           if (!isEnv && strings[i].includes("=")) {
  //             let allRemainingHaveEquals = true;
  //             for (let j = i; j < strings.length; j++) {
  //               if (!strings[j].includes("=")) {
  //                 allRemainingHaveEquals = false;
  //                 break;
  //               }
  //             }
  //             if (allRemainingHaveEquals) {
  //               isEnv = true;
  //             }
  //           }

  //           if (isEnv) {
  //             envp.push(strings[i]);
  //           } else {
  //             argv.push(strings[i]);
  //           }
  //         }

  //         send({
  //           type: "launch_request",
  //           path: path,
  //           argv: argv,
  //           envp: envp,
  //         });
  //       }
  //     },
  //   },
  // );
  recv("dispose", function (_msg) {
    console.log("running initproc cleanup routine...");
    Interceptor.detachAll();
    send({ type: "disposed" });
  });
}
if (processName === "amfid") {
  const cls = ObjC.classes.AMFIPathValidator_macos;
  const sel = "- validateWithError:";

  if (!cls || !cls["- validateWithError:"]) {
    console.log("Method not found:", sel);
  } else {
    Interceptor.attach(cls["- validateWithError:"].implementation, {
      onEnter(args) {
        this.self = new ObjC.Object(args[0]);

        console.log(
          "[AMFI] validateWithError: called on",
          this.self.toString(),
        );
      },

      onLeave(retval) {
        // Objective-C BOOL -> YES (1)
        retval.replace(ptr(1));

        console.log("[AMFI] validateWithError: -> forced YES");
      },
    });

    console.log("Hook installed for", sel);
  }
  recv("dispose", function (_msg) {
    console.log("running amfid cleanup routine...");
    Interceptor.detachAll();
    send({ type: "disposed" });
  });
}
// gui and dock and other interactive stuff
if (processName === "WindowServer") {
  const ColorCreateRGB = new NativeFunction(
    ResolvePrivateSignedSymbol("CoreGraphics", "CGColorCreateSRGB"),
    "pointer",
    ["double", "double", "double", "double"], // r, g, b, a
  );

  Interceptor.attach(
    ResolvePrivateSignedSymbol(
      "SkyLight",
      "_ZL25menu_bar_bounds_for_spaceP19PKGManagedMenuSpace",
    ),
    {
      onEnter(args) {
        if (Process.arch === "x64") {
          this.cgRectReturn = args[0];
        }
      },

      onLeave(retval) {
        if (Process.arch === "arm64") {
          this.context.d0 = 0.0;
          this.context.d1 = 0.0;
          this.context.d2 = 0.0;
          this.context.d3 = 0.0;
        } else if (Process.arch === "x64" && this.cgRectReturn) {
          this.cgRectReturn.writeDouble(0.0);
          this.cgRectReturn.add(8).writeDouble(0.0);
          this.cgRectReturn.add(16).writeDouble(0.0);
          this.cgRectReturn.add(24).writeDouble(0.0);
          retval.replace(this.cgRectReturn);
        }
      },
    },
  );
  Interceptor.attach(
    ResolvePrivateSignedSymbol("SkyLight", "WSWindowIsShadowEnabled"),
    {
      onLeave(retval) {
        retval.replace(ptr(0));
      },
    },
  );

  recv("dispose", function (_msg) {
    console.log("running server cleanup routine...");
    Interceptor.detachAll();
    send({ type: "disposed" });
  });
}
if (processName === "Dock") {
  const _WindowSetOpacity = new NativeFunction(
    ResolvePrivateSignedSymbol("SkyLight", "SLSSetWindowAlpha"),
    "int",
    ["int", "uint", "float"],
  );

  const _MainConnection = new NativeFunction(
    ResolvePrivateSignedSymbol("SkyLight", "SLSMainConnectionID"),
    "int",
    [],
  );

  function HideOrShowProcedure(hide) {
    let conn = _MainConnection();
    ObjC.choose(ObjC.classes.WAWindow, {
      onMatch(instance) {
        try {
          _WindowSetOpacity(conn, instance.$ivars.wid, hide ? 0.0 : 1.0);
        } catch (e) {
          console.log("Error reading instance: " + e);
        }
      },

      onComplete() {
        console.log("WALayerKitWindow instance enumeration complete");
      },
    });
  }
  HideOrShowProcedure(true);

  recv("dispose", function (_msg) {
    console.log("running dock cleanup routine...");

    HideOrShowProcedure(false);

    Interceptor.detachAll();
    send({ type: "disposed" });
  });
}
