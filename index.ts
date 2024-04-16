

import {
    frida_symtab,
} from './myfrida/tsmodules/fridautils'


import {
    getModuleBuildID,
    getModuleNDKVersion,
} from './myfrida/tsmodules/NDKUtils'

import {
    INFO_TYPE,                                                                                                                               
    mod as libpatchunityinfo,
} from './modinfos/libpatchgame'

import {
    HookFunAction,
    HookFunActionOptArgs,
    hookDlopen
} from './myfrida/tsmodules/HookFunAction'

const soname = 'libgame.so';

const addressToGhidraOffset = (pointer: NativePointer, moduleName?: string, moduleInfos: MODINFOS_TYPE = {}) => {
    let ghidraBase = getDefaultGhidraBase();
    if (moduleInfos && moduleName && moduleInfos[moduleName]) {
        const info = moduleInfos[moduleName];
        if(info.ghidraBase){ ghidraBase = info.ghidraBase; }
    } else {
        console.warn(`Using default Ghidra offset ${ghidraBase} for ${moduleName}`);
    }

    let module: Module | null = moduleName ? Process.findModuleByName(moduleName) : Process.findModuleByAddress(pointer);

    if (module) {
        return pointer.sub(module.base).add(ghidraBase);
    } else {
        throw new Error(`Cannot find a module named ${moduleName}`);
    }
}

const runFunWithExceptHandling = (f: () => void, modInfos: MODINFOS_TYPE = {}, spCount: number = 50, cb: (pe: Error) => void = (pe) => {}): void => {

    const inspectPointer = (p: NativePointer): string => {
        const module = Process.findModuleByAddress(p);
        if (module) {
            const moduleName = module.name;
            if (moduleName in modInfos) {
                const gp = addressToGhidraOffset(p, moduleName, modInfos);
                const offset = p.sub(module.base);
                return `${p} ${moduleName} @ ${offset} # ${gp}`;
            }
            return `${p} ${moduleName} @ ${p.sub(module.base)}`;
        } else {
            const m = Process.findModuleByAddress(p);
            if (m && modInfos) {
                const gp = addressToGhidraOffset(p, m.name, modInfos);
                const offset = p.sub(m.base);
                return `${p} ${m.name} @ ${offset} # ${gp}`;
            }
            const range = Process.findRangeByAddress(p);
            return `${p} ${module}, ${range}`;
        }
    }

    const handleExceptionContext = (e: Error): void => {
        if ((e as any).context !== undefined) {
            const context = (e as any).context;
            console.log('called from:\n' +
                Thread.backtrace(context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n');
            const pc = context.pc;
            console.log('pc', pc, inspectPointer(pc));
            const sp = context.sp;
            console.log('sp', sp);
            dumpMemory(sp, Process.pointerSize * spCount);
            for (let t = 0; t < spCount; t++) {
                const p = sp.add(t * Process.pointerSize).readPointer();
                console.log(t, inspectPointer(p));
            }
        }
    }

    try {
        f();
    } catch (_e) {
        const e: Error = _e as Error;
        handleExceptionContext(e);
        if (cb !== undefined) cb(e);
    }
}

const getAndroidAppInfo = ()=>{
    const ActivityThread = Java.use('android.app.ActivityThread');
    var currentApplication = ActivityThread.currentApplication();
    var context = currentApplication.getApplicationContext();

    
    return {
        applicationName                      : context.getPackageName().toString(),
        packageCodePath                      : context.getPackageCodePath                 (),
        packageResourcePath                  : context.getPackageResourcePath             (),
        cacheDir                             : context.getCacheDir                        ()?.getAbsolutePath().toString(),
        codeCacheDir                         : context.getCodeCacheDir                    ()?.getAbsolutePath().toString(),
        dataDir                              : context.getDataDir                         ()?.getAbsolutePath().toString(),
        externalCacheDir                     : context.getExternalCacheDir                ()?.getAbsolutePath().toString(),
        externalFilesDir                     : context.getExternalFilesDir            (null)?.getAbsolutePath().toString(),
        filesDir                             : context.getFilesDir                        ()?.getAbsolutePath().toString(),
        noBackupFilesDir                     : context.getNoBackupFilesDir                ()?.getAbsolutePath().toString(),
        obbDir                               : context.getObbDir                          ()?.getAbsolutePath().toString(),
    };
}

type MODINFOS_TYPE = {
    [key: string]:  // modulename 
    {
        ghidraBase?: NativePointer, // ghidra base

        buildId: string, // buildId of the module

        symbols: {

            [key: string]: {
                ghidraOffset: NativePointer,
            },
        }
    }
};

const getDefaultGhidraBase = ():NativePointer =>{
    if(Process.arch=='arm'  ){ return ptr(0x10000);     }
    if(Process.arch=='arm64'){ return ptr(0x100000);    }
    if(Process.arch=='ia32' ){ return ptr(0x400000);    }
    throw new Error(`unsupported arch ${Process.arch}`);
}
const ghidraOffset2Address = (soname:string,p:NativePointer, modinfos?:MODINFOS_TYPE) =>{
    let ghidraBase = getDefaultGhidraBase();
    if(undefined != modinfos){
        if(soname in modinfos) {
            let info = modinfos[soname]
            if(info.ghidraBase){ ghidraBase = info.ghidraBase; }
        }
    }
    let m = Process.findModuleByName(soname);
    if(m!=null){
        return p.add(m.base).sub(ghidraBase);
    }
    throw new Error(`can not found module info for ${soname}`)
}


const dumpMemory = (p: NativePointer, l: number = 0x20): void => {
    console.log(
        hexdump(p, {
            offset: 0,
            length: l,
            header: true,
            ansi: false,
        })
    );
};


const hookNativeApp = () => {

    const hooksForBisqueBaseUtilBQFileDecoder : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13BQFileDecoder15extractToMemoryEPNS_4Data5BQ1599BisqueKeyEPKcPNS0_14VariableBufferEj"),name:"bisqueBase::util::BQFileDecoder::extractToMemory(bisqueBase::Data::BQ159::BisqueKey*, char const*, bisqueBase::util::VariableBuffer*, unsigned int)", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13BQFileDecoder15extractToStreamEPNS_4Data5BQ1599BisqueKeyEPNS2_9NtyReaderEPNS_2IO6StreamEj"),name:"bisqueBase::util::BQFileDecoder::extractToStream(bisqueBase::Data::BQ159::BisqueKey*, bisqueBase::Data::NtyReader*, bisqueBase::IO::Stream*, unsigned int)", opts:{
    showCallStack:true,
    nparas:6,
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13BQFileDecoder13createDecoderEPNS_4Data5BQ1599BisqueKeyEPNS2_9NtyReaderEj"),name:"bisqueBase::util::BQFileDecoder::createDecoder(bisqueBase::Data::BQ159::BisqueKey*, bisqueBase::Data::NtyReader*, unsigned int)", opts:{}, },

    ];

    const hooksForLogging : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [

{p:ghidraOffset2Address(soname, ptr(0x1661b40)),  name:"log" , opts:{
    nparas:6,
    enterFun(args, tstr, thiz) {
        console.log(args[1].readUtf8String())
        console.log(args[2].readUtf8String())
        console.log(args[3].readUtf8String())
    },
},},

    ]

    const hooksForAAssetManager : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [

{p:Module.getExportByName("libandroid.so", "AAssetManager_open"         ),  name:"AAssetManager_open"              , opts:{
    // showCallStack:true,
    enterFun(args, tstr, thiz) {
        console.log(tstr, 'enter AAssetManager_open', args[1].readUtf8String());
    },
},},

{p:Module.getExportByName("libandroid.so", "AAsset_openFileDescriptor"  ),  name:"AAsset_openFileDescriptor"       , opts:{},},
{p:Module.getExportByName("libandroid.so", "AAsset_openFileDescriptor64"),  name:"AAsset_openFileDescriptor64"     , opts:{},},

    ]

    const hooksForBQ_android_io : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [

{p:Module.getExportByName(soname, "BQ_android_io_write"         ),  name:"BQ_android_io_write"       , opts:{},},
{p:Module.getExportByName(soname, "BQ_android_io_tell"          ),  name:"BQ_android_io_tell"        , opts:{},},
{p:Module.getExportByName(soname, "BQ_android_io_close"         ),  name:"BQ_android_io_close"       , opts:{},},
{p:Module.getExportByName(soname, "BQ_android_io_get_length"    ),  name:"BQ_android_io_get_length"  , opts:{},},
{p:Module.getExportByName(soname, "BQ_android_io_read"          ),  name:"BQ_android_io_read"        , opts:{},},
{p:Module.getExportByName(soname, "BQ_android_io_seek"          ),  name:"BQ_android_io_seek"        , opts:{},},
{p:Module.getExportByName(soname, "BQ_android_io_open"          ),  name:"BQ_android_io_open"        , opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr,`${args[0].readUtf8String()}`);
    },
},},

    ];

    const hooksForBQ_io : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [

// {p:Module.getExportByName(soname, "BQ_io_fdstat"             ), name :"BQ_io_fdstat"        , opts: {}, },

// {p:Module.getExportByName(soname, "BQ_io_stat"               ), name :"BQ_io_stat"          , opts: {
//     enterFun(args, tstr, thiz) {
//         console.log(tstr,`${args[0].readUtf8String()}`);
//     },
// }, },

// {p:Module.getExportByName(soname, "BQ_io_read"               ), name :"BQ_io_read"          , opts: {}, },

// {p:Module.getExportByName(soname, "BQ_io_copy"               ), name :"BQ_io_copy"          , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_resize"             ), name :"BQ_io_resize"        , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_exists"             ), name :"BQ_io_exists"        , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_remove"             ), name :"BQ_io_remove"        , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_dio_sectorsize"     ), name :"BQ_io_dio_sectorsize", opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_lock"               ), name :"BQ_io_lock"          , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_statfs"             ), name :"BQ_io_statfs"        , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_mkdir"              ), name :"BQ_io_mkdir"         , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_seek"               ), name :"BQ_io_seek"          , opts: {}, },

{p:Module.getExportByName(soname, "BQ_io_open"               ), name :"BQ_io_open"          , opts: {
    // showCallStack:true,
    enterFun(args, tstr, thiz) {
        console.log(tstr,`${args[0].readUtf8String()}`);
    },
}, },

// {p:Module.getExportByName(soname, "BQ_io_isdir"              ), name :"BQ_io_isdir"         , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_setup"              ), name :"BQ_io_setup"         , opts: {}, },

// {p:Module.getExportByName(soname, "BQ_io_write"              ), name :"BQ_io_write"         , opts: {}, },

{p:Module.getExportByName(soname, "BQ_io_opendir"            ), name :"BQ_io_opendir"       , opts: {
    enterFun(args, tstr, thiz) {
        console.log(tstr,`${args[0].readUtf8String()}`);
    },
}, },

// {p:Module.getExportByName(soname, "BQ_io_unlock"             ), name :"BQ_io_unlock"        , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_readdir"            ), name :"BQ_io_readdir"       , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_close"              ), name :"BQ_io_close"         , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_rmdir"              ), name :"BQ_io_rmdir"         , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_getcwd"             ), name :"BQ_io_getcwd"        , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_tell"               ), name :"BQ_io_tell"          , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_flush"              ), name :"BQ_io_flush"         , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_closedir"           ), name :"BQ_io_closedir"      , opts: {}, },
// {p:Module.getExportByName(soname, "BQ_io_chdir"              ), name :"BQ_io_chdir"         , opts: {}, },

    ];

    const hooksForBisqueBaseIoImplBQFileStream_Android : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [

{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android9getLengthEv"),name:"bisqueBase::IO::Impl::BQFileStream_Android::getLength()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android11getPositionEv"),name:"bisqueBase::IO::Impl::BQFileStream_Android::getPosition()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android5writeEPKvm"),name:"bisqueBase::IO::Impl::BQFileStream_Android::write(void const*, unsigned long)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android4seekExNS0_14tagSEEK_ORIGINE"),name:"bisqueBase::IO::Impl::BQFileStream_Android::seek(long long, bisqueBase::IO::tagSEEK_ORIGIN)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android5writeEPKvmm"),name:"bisqueBase::IO::Impl::BQFileStream_Android::write(void const*, unsigned long, unsigned long)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android14queryInterfaceE10_tagBQ_IIDPPv"),name:"bisqueBase::IO::Impl::BQFileStream_Android::queryInterface(_tagBQ_IID, void**)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_AndroidD0Ev"),name:"bisqueBase::IO::Impl::BQFileStream_Android::~BQFileStream_Android()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android4readEPvmm"),name:"bisqueBase::IO::Impl::BQFileStream_Android::read(void*, unsigned long, unsigned long)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_AndroidD1Ev"),name:"bisqueBase::IO::Impl::BQFileStream_Android::~BQFileStream_Android()", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android4openEPKcNS0_12tagFILE_MODEE"),name:"bisqueBase::IO::Impl::BQFileStream_Android::open(char const*, bisqueBase::IO::tagFILE_MODE)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr, `opening ${args[1].readUtf8String()} `);
    },

}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android5closeEv"),name:"bisqueBase::IO::Impl::BQFileStream_Android::close()", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android4openEv"),name:"bisqueBase::IO::Impl::BQFileStream_Android::open()", opts:{
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android8validateEv"),name:"bisqueBase::IO::Impl::BQFileStream_Android::validate()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase2IO4Impl20BQFileStream_Android4readEPvm"),name:"bisqueBase::IO::Impl::BQFileStream_Android::read(void*, unsigned long)", opts:{}, },

];


    const hooksForBisqueBaseGlobalNtyPool : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool8instanceEv"), name:"bisqueBase::util::GlobalNtyPool::instance()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15initalizeLocalsEv"), name:"bisqueBase::util::GlobalNtyPool::initalizeLocals()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool13getNetyByNameEPKcPPNS0_3GNP10NtyManagerE"), name:"bisqueBase::util::GlobalNtyPool::getNetyByName(char const*, bisqueBase::util::GNP::NtyManager**)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14getLastPatchIdEPKcPy"), name:"bisqueBase::util::GlobalNtyPool::getLastPatchId(char const*, unsigned long long*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18purgeLocalCacheAllEPNS0_3GNP30GNPAsyncOperationEventListenerEj"), name:"bisqueBase::util::GlobalNtyPool::purgeLocalCacheAll(bisqueBase::util::GNP::GNPAsyncOperationEventListener*, unsigned int)", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool24createLocalCacheFromListEPPKcj"), name:"bisqueBase::util::GlobalNtyPool::createLocalCacheFromList(char const**, unsigned int)", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19addPatchNTYInternalEPKcS3_yj"), name:"bisqueBase::util::GlobalNtyPool::addPatchNTYInternal(char const*, char const*, unsigned long long, unsigned int)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool21invalidateMemoryCacheEPKNS0_3GNP10NtyManagerE"), name:"bisqueBase::util::GlobalNtyPool::invalidateMemoryCache(bisqueBase::util::GNP::NtyManager const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14isContainsNameEPKc"), name:"bisqueBase::util::GlobalNtyPool::isContainsName(char const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14getStreamByAPUERKNS0_3GNP6NtyAPUEPPNS_2IO6StreamENS2_17GET_STREAM_METHODE"), name:"bisqueBase::util::GlobalNtyPool::getStreamByAPU(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::IO::Stream**, bisqueBase::util::GNP::GET_STREAM_METHOD)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15asyncAttachProcEPv"), name:"bisqueBase::util::GlobalNtyPool::asyncAttachProc(void*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool25waitForBackgroudOperationEv"), name:"bisqueBase::util::GlobalNtyPool::waitForBackgroudOperation()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool5clearEv"), name:"bisqueBase::util::GlobalNtyPool::clear()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool12attachVolumeEPKcPKNS_4Data5BQ1599BisqueKeyE"), name:"bisqueBase::util::GlobalNtyPool::attachVolume(char const*, bisqueBase::Data::BQ159::BisqueKey const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool11addPatchNTYEPKcS3_yj"), name:"bisqueBase::util::GlobalNtyPool::addPatchNTY(char const*, char const*, unsigned long long, unsigned int)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15purgeLocalCacheEPKcj"), name:"bisqueBase::util::GlobalNtyPool::purgeLocalCache(char const*, unsigned int)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18processAttachQueueEPKNS1_15GNPArtilleryJobE"), name:"bisqueBase::util::GlobalNtyPool::processAttachQueue(bisqueBase::util::GlobalNtyPool::GNPArtilleryJob const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19getAttachQueueCountEv"), name:"bisqueBase::util::GlobalNtyPool::getAttachQueueCount()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool12detachVolumeEPKcj"), name:"bisqueBase::util::GlobalNtyPool::detachVolume(char const*, unsigned int)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool9attachAllEPNS0_3GNP30GNPAsyncOperationEventListenerE"), name:"bisqueBase::util::GlobalNtyPool::attachAll(bisqueBase::util::GNP::GNPAsyncOperationEventListener*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool9initalizeEPKNS_4Data5BQ1599BisqueKeyE"), name:"bisqueBase::util::GlobalNtyPool::initalize(bisqueBase::Data::BQ159::BisqueKey const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15getCacheManagerEv"), name:"bisqueBase::util::GlobalNtyPool::getCacheManager()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool27getAttachQueueCountInternalEv"), name:"bisqueBase::util::GlobalNtyPool::getAttachQueueCountInternal()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool9terminateEv"), name:"bisqueBase::util::GlobalNtyPool::terminate()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool17createCacheByNameERKNS0_3GNP6NtyAPUEPPKc"), name:"bisqueBase::util::GlobalNtyPool::createCacheByName(bisqueBase::util::GNP::NtyAPU const&, char const**)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15getStreamByNameEPKcPPNS_2IO6StreamENS0_3GNP17GET_STREAM_METHODE"), name:"bisqueBase::util::GlobalNtyPool::getStreamByName(char const*, bisqueBase::IO::Stream**, bisqueBase::util::GNP::GET_STREAM_METHOD)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18lookupReadablePathEPKcPNS0_3GNP6NtyAPUE"), name:"bisqueBase::util::GlobalNtyPool::lookupReadablePath(char const*, bisqueBase::util::GNP::NtyAPU*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19createCacheFromListEPPKcj"), name:"bisqueBase::util::GlobalNtyPool::createCacheFromList(char const**, unsigned int)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPoolC2Ev"), name:"bisqueBase::util::GlobalNtyPool::GlobalNtyPool()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15findCacheByNameERKNS0_3GNP6NtyAPUEPPNS2_18NtyCacheDescriptorEPPKc"), name:"bisqueBase::util::GlobalNtyPool::findCacheByName(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyCacheDescriptor**, char const**)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19findCacheDescriptorERKNS0_3GNP6NtyAPUEPPNS2_18NtyCacheDescriptorE"), name:"bisqueBase::util::GlobalNtyPool::findCacheDescriptor(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyCacheDescriptor**)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16findVolumeByNameERKNS0_3GNP6NtyAPUEPPNS2_10NtyManagerEPj"), name:"bisqueBase::util::GlobalNtyPool::findVolumeByName(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyManager**, unsigned int*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool13getVolumeInfoEPKcPPNS0_3GNP10NtyManagerE"), name:"bisqueBase::util::GlobalNtyPool::getVolumeInfo(char const*, bisqueBase::util::GNP::NtyManager**)", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16createLocalCacheEPKc"), name:"bisqueBase::util::GlobalNtyPool::createLocalCache(char const*)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr, args[0].readUtf8String());
        //dumpMemory(args[0])
    },
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool12removeVolumeEPKc"), name:"bisqueBase::util::GlobalNtyPool::removeVolume(char const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool6removeEPKc"), name:"bisqueBase::util::GlobalNtyPool::remove(char const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14addAttachQueueEPNS0_3GNP18NTYPOOL_SPOOL_ITEME"), name:"bisqueBase::util::GlobalNtyPool::addAttachQueue(bisqueBase::util::GNP::NTYPOOL_SPOOL_ITEM*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18getVolumeInfoByAPUERKNS0_3GNP6NtyAPUEPPNS2_10NtyManagerE"), name:"bisqueBase::util::GlobalNtyPool::getVolumeInfoByAPU(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyManager**)", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool6attachEPKcPKNS_4Data5BQ1599BisqueKeyENS0_3GNP17ATTACH_NTY_METHODE"), name:"bisqueBase::util::GlobalNtyPool::attach(char const*, bisqueBase::Data::BQ159::BisqueKey const*, bisqueBase::util::GNP::ATTACH_NTY_METHOD)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr, args[0].readUtf8String())
    },
}, },


{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16createLocalCacheEPKcPNS0_3GNP10NtyPoolFSOE"), name:"bisqueBase::util::GlobalNtyPool::createLocalCache(char const*, bisqueBase::util::GNP::NtyPoolFSO*)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr, args[0].readUtf8String());
        //dumpMemory(args[0])
    },
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16getGlobalContextEv"), name:"bisqueBase::util::GlobalNtyPool::getGlobalContext()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPoolD0Ev"), name:"bisqueBase::util::GlobalNtyPool::~GlobalNtyPool()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool10isAttachedEPKc"), name:"bisqueBase::util::GlobalNtyPool::isAttached(char const*)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool6detachEPKcNS0_3GNP17DETACH_NTY_METHODE"), name:"bisqueBase::util::GlobalNtyPool::detach(char const*, bisqueBase::util::GNP::DETACH_NTY_METHOD)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPoolD2Ev"), name:"bisqueBase::util::GlobalNtyPool::~GlobalNtyPool()", opts:{}, },

    ];


    const hooksForFileRead : {p:NativePointer, name?:string, opts:HookFunActionOptArgs}[] = [


        {p:Module.getExportByName(soname, '_ZN7cocos2d11CCFileUtils11getFileDataEPKcS2_Pm'), name:'cocos2d::CCFileUtils::getFileData', opts:{

            // cocos2d::CCFileUtils::getFileData(char const*, char const*, unsigned long*)

            enterFun(args, tstr, thiz) {
                thiz.fn = args[1].readUtf8String();
                thiz.mod = args[2].readUtf8String();
                thiz.output = args[3];
                console.log(tstr,`read date with path ${thiz.fn} from ${thiz.mod}`);
            },

            leaveFun(retval, tstr, thiz) {
                dumpMemory(retval)
                dumpMemory(thiz.output)
            },

        }},

    ];


    const hooksForBisqueBaseUtilsNtyPool  :{p:NativePointer, name?:string, opts:HookFunActionOptArgs} [] = [

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool8instanceEv") , name: "bisqueBase::util::GlobalNtyPool::instance()" , opts:{}, }, 
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15initalizeLocalsEv") , name: "bisqueBase::util::GlobalNtyPool::initalizeLocals()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool13getNetyByNameEPKcPPNS0_3GNP10NtyManagerE") , name: "bisqueBase::util::GlobalNtyPool::getNetyByName(char const*, bisqueBase::util::GNP::NtyManager**)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14getLastPatchIdEPKcPy") , name: "bisqueBase::util::GlobalNtyPool::getLastPatchId(char const*, unsigned long long*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18purgeLocalCacheAllEPNS0_3GNP30GNPAsyncOperationEventListenerEj") , name: "bisqueBase::util::GlobalNtyPool::purgeLocalCacheAll(bisqueBase::util::GNP::GNPAsyncOperationEventListener*, unsigned int)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool24createLocalCacheFromListEPPKcj") , name: "bisqueBase::util::GlobalNtyPool::createLocalCacheFromList(char const**, unsigned int)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19addPatchNTYInternalEPKcS3_yj") , name: "bisqueBase::util::GlobalNtyPool::addPatchNTYInternal(char const*, char const*, unsigned long long, unsigned int)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool21invalidateMemoryCacheEPKNS0_3GNP10NtyManagerE") , name: "bisqueBase::util::GlobalNtyPool::invalidateMemoryCache(bisqueBase::util::GNP::NtyManager const*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14isContainsNameEPKc") , name: "bisqueBase::util::GlobalNtyPool::isContainsName(char const*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14getStreamByAPUERKNS0_3GNP6NtyAPUEPPNS_2IO6StreamENS2_17GET_STREAM_METHODE") , name: "bisqueBase::util::GlobalNtyPool::getStreamByAPU(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::IO::Stream**, bisqueBase::util::GNP::GET_STREAM_METHOD)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15asyncAttachProcEPv") , name: "bisqueBase::util::GlobalNtyPool::asyncAttachProc(void*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool25waitForBackgroudOperationEv") , name: "bisqueBase::util::GlobalNtyPool::waitForBackgroudOperation()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool5clearEv") , name: "bisqueBase::util::GlobalNtyPool::clear()" , opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool12attachVolumeEPKcPKNS_4Data5BQ1599BisqueKeyE") , name: "bisqueBase::util::GlobalNtyPool::attachVolume(char const*, bisqueBase::Data::BQ159::BisqueKey const*)" , opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr, 'enter attachVolume', args[1].readUtf8String());
    },
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool11addPatchNTYEPKcS3_yj") , name: "bisqueBase::util::GlobalNtyPool::addPatchNTY(char const*, char const*, unsigned long long, unsigned int)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15purgeLocalCacheEPKcj") , name: "bisqueBase::util::GlobalNtyPool::purgeLocalCache(char const*, unsigned int)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18processAttachQueueEPKNS1_15GNPArtilleryJobE") , name: "bisqueBase::util::GlobalNtyPool::processAttachQueue(bisqueBase::util::GlobalNtyPool::GNPArtilleryJob const*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19getAttachQueueCountEv") , name: "bisqueBase::util::GlobalNtyPool::getAttachQueueCount()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool12detachVolumeEPKcj") , name: "bisqueBase::util::GlobalNtyPool::detachVolume(char const*, unsigned int)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool9attachAllEPNS0_3GNP30GNPAsyncOperationEventListenerE") , name: "bisqueBase::util::GlobalNtyPool::attachAll(bisqueBase::util::GNP::GNPAsyncOperationEventListener*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool9initalizeEPKNS_4Data5BQ1599BisqueKeyE") , name: "bisqueBase::util::GlobalNtyPool::initalize(bisqueBase::Data::BQ159::BisqueKey const*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15getCacheManagerEv") , name: "bisqueBase::util::GlobalNtyPool::getCacheManager()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool27getAttachQueueCountInternalEv") , name: "bisqueBase::util::GlobalNtyPool::getAttachQueueCountInternal()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool9terminateEv") , name: "bisqueBase::util::GlobalNtyPool::terminate()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool17createCacheByNameERKNS0_3GNP6NtyAPUEPPKc") , name: "bisqueBase::util::GlobalNtyPool::createCacheByName(bisqueBase::util::GNP::NtyAPU const&, char const**)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15getStreamByNameEPKcPPNS_2IO6StreamENS0_3GNP17GET_STREAM_METHODE") , name: "bisqueBase::util::GlobalNtyPool::getStreamByName(char const*, bisqueBase::IO::Stream**, bisqueBase::util::GNP::GET_STREAM_METHOD)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18lookupReadablePathEPKcPNS0_3GNP6NtyAPUE") , name: "bisqueBase::util::GlobalNtyPool::lookupReadablePath(char const*, bisqueBase::util::GNP::NtyAPU*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19createCacheFromListEPPKcj") , name: "bisqueBase::util::GlobalNtyPool::createCacheFromList(char const**, unsigned int)" , opts:{}, },
// {p:Module.getExportByName(soname, "_ZN10bisfindVolumeByNamequeBase4util13GlobalNtyPoolC2Ev") , name: "bisqueBase::util::GlobalNtyPool::GlobalNtyPool()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool15findCacheByNameERKNS0_3GNP6NtyAPUEPPNS2_18NtyCacheDescriptorEPPKc") , name: "bisqueBase::util::GlobalNtyPool::findCacheByName(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyCacheDescriptor**, char const**)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool19findCacheDescriptorERKNS0_3GNP6NtyAPUEPPNS2_18NtyCacheDescriptorE") , name: "bisqueBase::util::GlobalNtyPool::findCacheDescriptor(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyCacheDescriptor**)" , opts:{}, },

//{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16findVolumeByNameERKNS0_3GNP6NtyAPUEPPNS2_10NtyManagerEPj") , name: "bisqueBase::util::GlobalNtyPool::findVolumeByName(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyManager**, unsigned int*)" , opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool13getVolumeInfoEPKcPPNS0_3GNP10NtyManagerE") , name: "bisqueBase::util::GlobalNtyPool::getVolumeInfo(char const*, bisqueBase::util::GNP::NtyManager**)" , opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16createLocalCacheEPKc") , name: "bisqueBase::util::GlobalNtyPool::createLocalCache(char const*)" , opts:{
    enterFun(args, tstr, thiz) {
        console.log(args[0].readUtf8String())
    },
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool12removeVolumeEPKc") , name: "bisqueBase::util::GlobalNtyPool::removeVolume(char const*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool6removeEPKc") , name: "bisqueBase::util::GlobalNtyPool::remove(char const*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool14addAttachQueueEPNS0_3GNP18NTYPOOL_SPOOL_ITEME") , name: "bisqueBase::util::GlobalNtyPool::addAttachQueue(bisqueBase::util::GNP::NTYPOOL_SPOOL_ITEM*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool18getVolumeInfoByAPUERKNS0_3GNP6NtyAPUEPPNS2_10NtyManagerE") , name: "bisqueBase::util::GlobalNtyPool::getVolumeInfoByAPU(bisqueBase::util::GNP::NtyAPU const&, bisqueBase::util::GNP::NtyManager**)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool6attachEPKcPKNS_4Data5BQ1599BisqueKeyENS0_3GNP17ATTACH_NTY_METHODE") , name: "bisqueBase::util::GlobalNtyPool::attach(char const*, bisqueBase::Data::BQ159::BisqueKey const*, bisqueBase::util::GNP::ATTACH_NTY_METHOD)" , opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16createLocalCacheEPKcPNS0_3GNP10NtyPoolFSOE") , name: "bisqueBase::util::GlobalNtyPool::createLocalCache(char const*, bisqueBase::util::GNP::NtyPoolFSO*)" , opts:{
    enterFun(args, tstr, thiz) {
        console.log(args[0].readUtf8String())
    },
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool16getGlobalContextEv") , name: "bisqueBase::util::GlobalNtyPool::getGlobalContext()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPoolD0Ev") , name: "bisqueBase::util::GlobalNtyPool::~GlobalNtyPool()" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool10isAttachedEPKc") , name: "bisqueBase::util::GlobalNtyPool::isAttached(char const*)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPool6detachEPKcNS0_3GNP17DETACH_NTY_METHODE") , name: "bisqueBase::util::GlobalNtyPool::detach(char const*, bisqueBase::util::GNP::DETACH_NTY_METHOD)" , opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util13GlobalNtyPoolD2Ev") , name: "bisqueBase::util::GlobalNtyPool::~GlobalNtyPool()" , opts:{}, },

];

    const hooksForBisqueBaseBQStorage  :{p:NativePointer, name?:string, opts:HookFunActionOptArgs} [] = [

{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage6forgetERNS_4util11rectilinearINS1_3GNP11GNPStoreKeyEN5boost4asio10tallocatorIS4_EEEE"), name:"bisqueBase::BQStorage::forget(bisqueBase::util::rectilinear<bisqueBase::util::GNP::GNPStoreKey, boost::asio::tallocator<bisqueBase::util::GNP::GNPStoreKey> >&)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage7disposeEv"), name:"bisqueBase::BQStorage::dispose()", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage5storeEPKcS2_ji"), name:"bisqueBase::BQStorage::store(char const*, char const*, unsigned int, int)", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage5gettyEPKcb"), name:"bisqueBase::BQStorage::getty(char const*, bool)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr,` ${args[1].readUtf8String()} `);
    },
    leaveFun(retval, tstr, thiz) {
        console.log(tstr, retval.readUtf8String())
    },
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase4util8CacheMapINS_9BQStorage14StoreSchlusselEPNS2_11StoreObzektES3_N5boost10TypeHelperIS3_EEE7_removeERKS3_"), name:"bisqueBase::util::CacheMap<bisqueBase::BQStorage::StoreSchlussel, bisqueBase::BQStorage::StoreObzekt*, bisqueBase::BQStorage::StoreSchlussel, boost::TypeHelper<bisqueBase::BQStorage::StoreSchlussel> >::_remove(bisqueBase::BQStorage::StoreSchlussel const&)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr,` ${args[1].readUtf8String()} `);
    },
}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage14StoreSchlusselC2ERKS1_"), name:"bisqueBase::BQStorage::StoreSchlussel::StoreSchlussel(bisqueBase::BQStorage::StoreSchlussel const&)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorageD0Ev"), name:"bisqueBase::BQStorage::~BQStorage()", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage14lookupFilePathEPKcjPcj"), name:"bisqueBase::BQStorage::lookupFilePath(char const*, unsigned int, char*, unsigned int)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr, "lookup", args[0].readUtf8String())
        dumpMemory(args[2])
    },

}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorageD2Ev"), name:"bisqueBase::BQStorage::~BQStorage()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage6existsEPKcj"), name:"bisqueBase::BQStorage::exists(char const*, unsigned int)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN5boost6soviet12spotted_lockIN10bisqueBase9BQStorageEED2Ev"), name:"boost::soviet::spotted_lock<bisqueBase::BQStorage>::~spotted_lock()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util8CacheMapINS_9BQStorage14StoreSchlusselEPNS2_11StoreObzektES3_N5boost10TypeHelperIS3_EEE6_clearEv"), name:"bisqueBase::util::CacheMap<bisqueBase::BQStorage::StoreSchlussel, bisqueBase::BQStorage::StoreObzekt*, bisqueBase::BQStorage::StoreSchlussel, boost::TypeHelper<bisqueBase::BQStorage::StoreSchlussel> >::_clear()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util8CacheMapINS_9BQStorage14StoreSchlusselEPNS2_11StoreObzektES3_N5boost10TypeHelperIS3_EEE8_destroyEv"), name:"bisqueBase::util::CacheMap<bisqueBase::BQStorage::StoreSchlussel, bisqueBase::BQStorage::StoreObzekt*, bisqueBase::BQStorage::StoreSchlussel, boost::TypeHelper<bisqueBase::BQStorage::StoreSchlussel> >::_destroy()", opts:{}, },
//{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage14StoreSchlusselD0Ev"), name:"bisqueBase::BQStorage::StoreSchlussel::~StoreSchlussel()", opts:{}, },
//{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage14StoreSchlusselD2Ev"), name:"bisqueBase::BQStorage::StoreSchlussel::~StoreSchlussel()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage10initializeEv"), name:"bisqueBase::BQStorage::initialize()", opts:{}, },
//{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage11StoreObzektD0Ev"), name:"bisqueBase::BQStorage::StoreObzekt::~StoreObzekt()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util8CacheMapINS_9BQStorage14StoreSchlusselEPNS2_11StoreObzektES3_N5boost10TypeHelperIS3_EEE4_addERKS3_RKS5_"), name:"bisqueBase::util::CacheMap<bisqueBase::BQStorage::StoreSchlussel, bisqueBase::BQStorage::StoreObzekt*, bisqueBase::BQStorage::StoreSchlussel, boost::TypeHelper<bisqueBase::BQStorage::StoreSchlussel> >::_add(bisqueBase::BQStorage::StoreSchlussel const&, bisqueBase::BQStorage::StoreObzekt* const&)", opts:{}, },
//{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage11StoreObzektD2Ev"), name:"bisqueBase::BQStorage::StoreObzekt::~StoreObzekt()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage13getReadStreamEPKcjPPNS_2IO6StreamE"), name:"bisqueBase::BQStorage::getReadStream(char const*, unsigned int, bisqueBase::IO::Stream**)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorageC2Ev"), name:"bisqueBase::BQStorage::BQStorage()", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage12readToBufferEPKcjPPNS_4util14VariableBufferE"), name:"bisqueBase::BQStorage::readToBuffer(char const*, unsigned int, bisqueBase::util::VariableBuffer**)", opts:{}, },
{p:Module.getExportByName(soname, "_ZN10bisqueBase4util8CacheMapINS_9BQStorage14StoreSchlusselEPNS2_11StoreObzektES3_N5boost10TypeHelperIS3_EEE9_do_splayERKS3_"), name:"bisqueBase::util::CacheMap<bisqueBase::BQStorage::StoreSchlussel, bisqueBase::BQStorage::StoreObzekt*, bisqueBase::BQStorage::StoreSchlussel, boost::TypeHelper<bisqueBase::BQStorage::StoreSchlussel> >::_do_splay(bisqueBase::BQStorage::StoreSchlussel const&)", opts:{}, },

{p:Module.getExportByName(soname, "_ZN10bisqueBase9BQStorage14StoreSchlusselC2EPKc"), name:"bisqueBase::BQStorage::StoreSchlussel::StoreSchlussel(char const*)", opts:{
    enterFun(args, tstr, thiz) {
        console.log(tstr,`${args[1].readUtf8String()}`);
    },
}, },

    ];

    [

        // ...hooksForAAssetManager,
        // ...hooksForBisqueBaseUtilBQFileDecoder,
        // ...hooksForBQ_io,
        // ...hooksForLogging,
        // ...hooksForBQ_android_io,
        // ...hooksForBisqueBaseIoImplBQFileStream_Android,
        // ...hooksForBisqueBaseGlobalNtyPool,
        // ...hooksForBisqueBaseBQStorage,
        // ...hooksForFileRead,
    ].forEach((h : {p:NativePointer, name?:string, opts?:{[key:string]:any}})=>{
        console.log('hooking', JSON.stringify(h))
        let {p, name, opts} = h;
        name = name ?? p.toString();
        HookFunAction.addInstance(p, new HookFunAction({ ...opts, name}))
    })

}

const patchApp = ()=>{
    const fun = new NativeFunction(Module.getExportByName(soname, "BQ_independence_set_log_level"), 'void',['int']);
    fun(0);
}

const testApp = ()=>{
    const fun = new NativeFunction(Module.getExportByName(soname, "BQ_independence_get_log_level"), 'int',[]);
    console.log('log level', fun())

    console.log('NDK version',getModuleNDKVersion(soname))
}


let patchLib : INFO_TYPE | null = null;

const loadPatchlib = ()=>{
    if (patchLib == null) {

        patchLib = libpatchunityinfo.load(
            `/data/local/tmp//libpatchgame.so`,
            [
                soname,
            ],
            {
                ...frida_symtab,
            },
        );
        // console.log(JSON.stringify(lib))
        const runInit = () => {
            if(0){
                if (patchLib) {
                    const fun = new NativeFunction(patchLib.symbols.init, 'int', ['pointer', 'pointer']);
                    const m = Process.getModuleByName(soname);
                    const appinfo = getAndroidAppInfo();
                    const pdatadir = Memory.allocUtf8String(appinfo.dataDir);
                    const ret = fun(m.base, pdatadir)
                }
            }
        }
        if (1) {
            try{
                runInit();
            }
            catch(e){
                console.log(e)
                let context = (e as any).context;
                console.log('context', context, JSON.stringify(context))
                const pc  = context.pc; console.log('pc', pc, addressToGhidraOffset(pc))
                const lr  = context.lr; console.log('lr', lr, addressToGhidraOffset(lr))
            }
        }
        else {
            runInit();
        }

    }
}

const test = ()=>{

    const handleLoadSo = ()=>{
        patchApp();
        //findFuns("AAssetManager_open");
        hookNativeApp();

        loadPatchlib();

        testApp();

    }

    const m = Process.findModuleByName(soname);
    if(m==null){
        hookDlopen(soname, ()=>{
            handleLoadSo();
        })
    }
    else{
        handleLoadSo();
    }
    
}

console.log('##################################################')
test();
