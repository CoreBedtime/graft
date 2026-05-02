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

let gReplacement = Memory.allocUtf8String(
  "/Volumes/Bedtime/Developer/kaldera/output/kproc-init/main",
);

const dispatch_data_create_map = new NativeFunction(
  ResolvePrivateSignedSymbol(
    "/usr/lib/system/libdispatch.dylib",
    "dispatch_data_create_map",
  ),
  "pointer",
  ["pointer", "pointer", "pointer"],
);

// initproc / codesigning
if (processName === "launchd") {
  Interceptor.attach(
    ResolvePrivateSignedSymbol(
      "/usr/lib/system/libxpc.dylib",
      "xpc_data_create_with_dispatch_data",
    ),
    {
      onEnter(args) {
        const dispatchData = args[0];

        // Allocate output pointers for the mapped buffer and size
        const bufPtrOut = Memory.alloc(Process.pointerSize);
        const sizePtrOut = Memory.alloc(Process.pointerSize);

        // Map the dispatch_data to a contiguous buffer
        dispatch_data_create_map(dispatchData, bufPtrOut, sizePtrOut);

        const bufPtr = bufPtrOut.readPointer();
        const size = sizePtrOut.readUInt();

        if (bufPtr.isNull() || size === 0) return;

        // Read the raw bytes from the mapped buffer
        const bytes = bufPtr.readByteArray(size);
        const view = new Uint8Array(bytes);

        // Extract null-terminated C strings from the buffer
        const strings = [];
        let start = 0;

        for (let i = 0; i <= view.length; i++) {
          const isEnd = i === view.length || view[i] === 0;

          if (isEnd) {
            if (i > start) {
              const slice = view.slice(start, i);
              // Filter to only printable ASCII (0x20–0x7E), min length 4
              const allPrintable = slice.every((b) => b >= 0x20 && b <= 0x7e);
              if (allPrintable && slice.length >= 4) {
                strings.push(String.fromCharCode(...slice));
              }
            }
            start = i + 1;
          }
        }

        if (strings.length > 0) {
          console.log(`[xpc_data_create_with_dispatch_data] size=${size}`);
          strings.forEach((s) => console.log(`  -> "${s}"`));
        }
      },
    },
  );
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
