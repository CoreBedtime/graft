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

const LibName = "SkyLight";

const _ShapeWindowWithRectAddr = ResolvePrivateSignedSymbol(
  LibName,
  "WSShapeWindowWithRect",
);
const _ShapeWindowWithRect = _ShapeWindowWithRectAddr
  ? new NativeFunction(_ShapeWindowWithRectAddr, "void", [
      "pointer",
      ["double", "double", "double", "double"],
    ])
  : null;

const _WindowIsValidAddr = ResolvePrivateSignedSymbol(
  LibName,
  "WSWindowIsInvalid",
);
const _WindowIsValid = _WindowIsValidAddr
  ? new NativeFunction(_WindowIsValidAddr, "uint8", ["pointer"])
  : null;

const _WindowGetOwningProcessIdAddr = ResolvePrivateSignedSymbol(
  LibName,
  "WSWindowGetOwningPID",
);
const _WindowGetOwningProcessId = _WindowGetOwningProcessIdAddr
  ? new NativeFunction(_WindowGetOwningProcessIdAddr, "int", ["pointer"])
  : null;

const _OrderWindowListSpaceSwitchOptionsAddr = ResolvePrivateSignedSymbol(
  LibName,
  "_ZL36CGXOrderWindowListSpaceSwitchOptionsP13CGXConnectionPKjPK10CGSOrderOpS2_jb",
);
const _OrderWindowListSpaceSwitchOptions =
  _OrderWindowListSpaceSwitchOptionsAddr
    ? new NativeFunction(_OrderWindowListSpaceSwitchOptionsAddr, "void", [
        "pointer", // connection
        "pointer", // window list (int *)
        "pointer", // order operations (CGSOrderOp *)
        "pointer", // relative window ID (int *)
        "uint", // count
        "uint", // options
      ])
    : null;

const _BindLocalClientContextAddr = ResolvePrivateSignedSymbol(
  LibName,
  "_ZN9CGXWindow28bind_local_ca_client_contextEP9CAContextb",
);
const _BindLocalClientContext = _BindLocalClientContextAddr
  ? new NativeFunction(_BindLocalClientContextAddr, "void", [
      "pointer",
      "pointer",
      "int64",
    ])
  : null;

const _WindowLayerBackingTakeOwnershipOfContextAddr =
  ResolvePrivateSignedSymbol(LibName, "WSCALayerBackingTakeOwnershipOfContext");
const _WindowLayerBackingTakeOwnershipOfContext =
  _WindowLayerBackingTakeOwnershipOfContextAddr
    ? new NativeFunction(
        _WindowLayerBackingTakeOwnershipOfContextAddr,
        "void",
        ["pointer", "pointer"],
      )
    : null;

const _ScheduleUpdateAllDisplaysAddr = ResolvePrivateSignedSymbol(
  LibName,
  "CGXScheduleUpdateAllDisplays",
);
const _ScheduleUpdateAllDisplays = _ScheduleUpdateAllDisplaysAddr
  ? new NativeFunction(_ScheduleUpdateAllDisplaysAddr, "void", [
      "int64",
      "int64",
    ])
  : null;

const _InvalidateDisplayShapeAddr = ResolvePrivateSignedSymbol(
  LibName,
  "CGXInvalidateDisplayShape",
);
const _InvalidateDisplayShape = _InvalidateDisplayShapeAddr
  ? new NativeFunction(_InvalidateDisplayShapeAddr, "void", [
      "int64",
      "int64",
      "int64",
    ])
  : null;

const _StartSubsidiaryServicesAddr = ResolvePrivateSignedSymbol(
  LibName,
  "CGXStartSubsidiaryServices",
);
const _StartSubsidiaryServices = _StartSubsidiaryServicesAddr
  ? new NativeFunction(_StartSubsidiaryServicesAddr, "pointer", ["int64"])
  : null;

const __SERVER_COMMIT_STARTAddr = ResolvePrivateSignedSymbol(
  LibName,
  "_ZN27WSCAContextScopeTransaction18addContextToCommitEP9CAContext",
);
const __SERVER_COMMIT_START = __SERVER_COMMIT_STARTAddr
  ? new NativeFunction(__SERVER_COMMIT_STARTAddr, "void", [
      "pointer",
      "pointer",
    ])
  : null;

const __SERVER_COMMIT_ENDAddr = ResolvePrivateSignedSymbol(
  LibName,
  "_ZN27WSCAContextScopeTransactionD1Ev",
);
const __SERVER_COMMIT_END = __SERVER_COMMIT_ENDAddr
  ? new NativeFunction(__SERVER_COMMIT_ENDAddr, "void", ["pointer"])
  : null;

const _WindowCreateAddr = ResolvePrivateSignedSymbol(LibName, "WSWindowCreate");
const _WindowCreate = _WindowCreateAddr
  ? new NativeFunction(_WindowCreateAddr, "pointer", [
      "int64",
      "uint",
      "pointer",
      "int",
    ])
  : null;

// msin start
//
const processName = ObjC.classes.NSProcessInfo.processInfo()
  .processName()
  .toString();
if (processName === "WindowServer") {
  let gWindowRoot = null;
  let gRootContextPtr = null;
  let gWindowRootBounds = [0, 0, 1800, 1169]; // x, y, width, height

  const CGRegionCreateWithRect = new NativeFunction(
    ResolvePrivateSignedSymbol("CoreGraphics", "CGRegionCreateWithRect"),
    "pointer",
    ["double", "double", "double", "double"],
  );

  const CGColorCreateSRGB = new NativeFunction(
    ResolvePrivateSignedSymbol("CoreGraphics", "CGColorCreateSRGB"),
    "pointer",
    ["double", "double", "double", "double"],
  );

  // CALayer -setFrame: takes CGRect by value. frida-objc-bridge can't convert
  // a plain JS array for struct arguments, so call the imp directly.
  const _CALayer_setFrame = new NativeFunction(
    ObjC.classes.CALayer["- setFrame:"].implementation,
    "void",
    ["pointer", "pointer", "double", "double", "double", "double"],
  );
  function CALayerSetFrame(layer, x, y, w, h) {
    _CALayer_setFrame(layer.handle, ObjC.selector("setFrame:"), x, y, w, h);
  }

  function OrderWindow(window_ptr, orderOp) {
    const windowID = window_ptr.readU32();
    const windowIDPtr = Memory.alloc(4);
    windowIDPtr.writeU32(windowID);

    const orderOpPtr = Memory.alloc(4);
    orderOpPtr.writeU32(orderOp);

    const relativeWindowIDPtr = Memory.alloc(4);
    relativeWindowIDPtr.writeU32(0);

    _OrderWindowListSpaceSwitchOptions(
      ptr(0), // connection
      windowIDPtr, // window list (int *)
      orderOpPtr, // order operations
      relativeWindowIDPtr, // relative window ID
      1, // count
      0, // options
    );
  }

  function UpdateProteinRoot() {
    const [x, y, w, h] = gWindowRootBounds;
    const Region = CGRegionCreateWithRect(x, y, w, h);

    const { CAContext, CATransaction, CALayer, NSDictionary } = ObjC.classes;

    if (gWindowRoot === null) {
      gWindowRoot = _WindowCreate(0, 5, Region, 6145);

      gRootContextPtr = CAContext.localContextWithOptions_(
        NSDictionary.dictionary(),
      );
      _BindLocalClientContext(gWindowRoot, gRootContextPtr.handle, 0);
      _WindowLayerBackingTakeOwnershipOfContext(
        gWindowRoot,
        gRootContextPtr.handle,
      );

      const intptr = Memory.alloc(8);
      intptr.writeU64(0);

      CATransaction.begin();
      CATransaction.setDisableActions_(true);
      __SERVER_COMMIT_START(intptr, gRootContextPtr.handle);

      const rootlayer = CALayer.new();
      CALayerSetFrame(rootlayer, x, y, w, h);
      rootlayer.setBackgroundColor_(CGColorCreateSRGB(1, 0, 0, 1));

      gRootContextPtr.setLayer_(rootlayer);
      __SERVER_COMMIT_END(intptr);
      CATransaction.commit();

      //OrderWindow(gWindowRoot, 1);
      console.log(`window created with bounds: ${gWindowRootBounds}`);
    } else {
      const intptr = Memory.alloc(8);
      intptr.writeU64(0);

      CATransaction.begin();
      CATransaction.setDisableActions_(true);
      __SERVER_COMMIT_START(intptr, gRootContextPtr.handle);

      gRootContextPtr
        .layer()
        .setBackgroundColor_(CGColorCreateSRGB(0.5, 0, 0, 1.0));

      __SERVER_COMMIT_END(intptr);
      CATransaction.commit();

      _InvalidateDisplayShape(0, gWindowRoot, Region);
      _ScheduleUpdateAllDisplays(0, 0);
      //OrderWindow(gWindowRoot, 1);
    }
  }

  let shouldRun = true;

  const intervalId = setInterval(() => {
    if (!shouldRun) {
      console.log("render stopped.");
      clearInterval(intervalId);
      return;
    }

    try {
      UpdateProteinRoot();
    } catch (e) {
      console.log("render err: " + e);
    }
  }, 8);

  recv("dispose", function (_msg) {
    console.log("running cleanup routine...");

    shouldRun = false;
    clearInterval(intervalId); // stop interval immediately
    Interceptor.detachAll();

    _ShapeWindowWithRect(gWindowRoot, 0, 0, 20, 20);

    send({ type: "disposed" });
  });
}
if (processName === "Dock") {
  recv("dispose", function (_msg) {
    console.log("running cleanup routine...");
    Interceptor.detachAll();
    send({ type: "disposed" });
  });
}
