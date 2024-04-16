
#include <stdlib.h>
#include <map>
#include <string>
#include <string.h>

#include "c/misc/utils.h"
#include "c/misc/mycpp.h"


// libgame.so



namespace bisqueBase {
    namespace util{
        namespace GNP{
            struct NtyAPU{
                void set(char const*);
                unsigned char _0x0[0x500];
                NtyAPU(){
                    memset(this, 0, sizeof(NtyAPU));
                }
            };   
            struct GNPStoreKey{
                void* vtab;
                char* _name;
                unsigned char _0x4[0x2c];
            };
            struct NtyCacheDescriptor{
                void* vtab;
            };
            struct NtyCacheManager{
                void* vtab;
                std::map<GNPStoreKey, GNP::NtyCacheDescriptor*> _map;
                int getCacheByName(char const*, GNP::NtyCacheDescriptor**);
            };
            struct NtyManager{
                void* vtab;
            };
        };
        struct GlobalNtyPool{
            static GlobalNtyPool* getGlobalContext();
            static GlobalNtyPool* instance();
            int findVolumeByName(GNP::NtyAPU const&, GNP::NtyManager**, unsigned int*); // x8
            unsigned char _0x0[0x28];
            GNP::NtyCacheManager* _cacheManager;
        };
    };
};


extern "C" int __attribute__((visibility("default"))) init(unsigned char* base, const char* datadir ) {

    const char* itemName = "opening_scroll_b.png";

    bisqueBase::util::GNP::NtyAPU apu;
    apu.set(itemName);

    auto *globalNtyPool = bisqueBase::util::GlobalNtyPool::instance();
    LOG_INFOS("globalNtyPool %p ", globalNtyPool);

    if (globalNtyPool != nullptr)
    {

        auto *cacheManager = globalNtyPool->_cacheManager;

        if (cacheManager != nullptr) {

            LOG_INFOS(" m size %d", cacheManager->_map.size());

            for(auto it = cacheManager->_map.begin(); it!= cacheManager->_map.end(); it ++ ){
                auto& key    = it->first ;
                auto* pcache = it->second;
                char* name = key._name;
                LOG_INFOS("pcache %s %p ", name, pcache);
            }

            unsigned int id = 0;
            // // auto  ret = globalNtyPool->findVolumeByName(apu, &manager, &id);
            bisqueBase::util::GNP::NtyCacheDescriptor *cacheDescriptor = nullptr;

            auto ret = cacheManager->getCacheByName(itemName, &cacheDescriptor);
            LOG_INFOS("ret %d id %d  cacheDescriptor %p manager %p", ret, id, cacheDescriptor, cacheManager);
            //if(cacheDescriptor!=nullptr) {
            //    delete cacheDescriptor;
            //}
        }
    }

    LOG_INFOS("ret %d ", sizeof(std::string));

    _frida_log("Initiaized ok ");
    return 0;
}

