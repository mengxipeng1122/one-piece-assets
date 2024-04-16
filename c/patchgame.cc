
#include <stdlib.h>
#include <map>
#include <list>
#include <string>
#include <string.h>

#include "c/misc/utils.h"
#include "c/misc/mycpp.h"


// libgame.so





namespace bisqueBase {
    namespace IO{
        struct Stream{

        };
    };
    namespace Data{
        namespace BQ159{
            struct BisqueKey{
                
            };
        }
        struct NtyReader{
            int getStream(IO::Stream**, unsigned int, unsigned int);
        };
    }
    namespace util{

        struct BQFileDecoder{
            static int extractToStream(bisqueBase::Data::BQ159::BisqueKey*, bisqueBase::Data::NtyReader*, bisqueBase::IO::Stream*, unsigned int);
            static BQFileDecoder* createDecoder(bisqueBase::Data::BQ159::BisqueKey*, bisqueBase::Data::NtyReader*, unsigned int);
        };
        
        namespace GNP{
            struct NtyCacheDescriptor;
            struct NtyAPU{
                void* vtab;
                unsigned char _0x8[0x400];
                char* name;
                unsigned char _0x410[0x100];
                void set(char const*);
                NtyAPU(){
                    memset(this, 0, sizeof(NtyAPU));
                }
            };   
            struct GNPStoreKey{
                void* vtab;
                char* _name;
                unsigned char _0x4[0x2c];
            };
            struct NtyCacheStore {
                void* vtab;
                unsigned char _0x8[0x8];
                std::map<GNPStoreKey, GNP::NtyCacheDescriptor*> _map;
                int getCacheByName(char const*, bisqueBase::util::GNP::NtyCacheDescriptor**);
            };
            struct NtyCacheDescriptor{
                void* vtab;
                unsigned char _0x8[0x140];
                int validate();
                NtyCacheDescriptor(char const*);
            };
            struct NtyCacheManager{
                void* vtab;
                std::map<GNPStoreKey, GNP::NtyCacheDescriptor*> _map;
                int getCacheByName(char const*, GNP::NtyCacheDescriptor**);
            };
            struct NtyManager{
                void* vtab;
                unsigned char _0x8[0x10];
                unsigned char useCache;
                unsigned char _0x19[0x3];
                unsigned char _0x1c[0x14];
                NtyCacheStore* _cacheStore;
                std::map<GNPStoreKey, GNP::NtyCacheDescriptor*>* _map;
                unsigned char _x40[0x7c8];
                std::list<void*> _list;
                int segments;
                int getCacheDescriptorByName(char const*, GNP::NtyCacheDescriptor**);
                unsigned int findByTitile(char const*, unsigned int*, GNP::NtyManager**);
            };
        };
        struct GlobalNtyPool{
            static GlobalNtyPool* getGlobalContext();
            static GlobalNtyPool* instance();
            int findVolumeByName(GNP::NtyAPU const&, GNP::NtyManager**, unsigned int*); // x8
            unsigned char _0x0[0x28];
            GNP::NtyCacheManager* _cacheManager;
            GNP::NtyCacheManager* getCacheManager();
            int getAttachQueueCount();
        };
    };
};

int testManager() {

    const char* itemName = "opening_scroll_b.png";

    bisqueBase::util::GNP::NtyAPU apu;
    apu.set(itemName);
    LOG_INFOS("apu %s ", apu.name);

    auto *globalNtyPool = bisqueBase::util::GlobalNtyPool::instance();
    LOG_INFOS("globalNtyPool %p %d ", globalNtyPool, globalNtyPool->getAttachQueueCount());

    if (globalNtyPool != nullptr) {

        unsigned int id = 0;
        bisqueBase::util::GNP::NtyManager *manager = nullptr;
        auto ret = globalNtyPool->findVolumeByName(apu, &manager, &id);
        LOG_INFOS("ret %d %p", ret, manager);
        if(manager != nullptr){
            _frida_hexdump(manager, 0x40);
            auto* cacheStore = manager->_cacheStore;
            LOG_INFOS(" cacheStore %p ", cacheStore);
            bisqueBase::util::GNP::NtyCacheDescriptor *cacheDescriptor = nullptr;
            auto ret1 = manager->getCacheDescriptorByName(itemName, &cacheDescriptor);
            LOG_INFOS("ret %d id %d  cacheDescriptor %p manager %p", ret1, id, cacheDescriptor, manager);
            bisqueBase::util::GNP::NtyManager *manager1 = nullptr;
            auto ret2 = manager->findByTitile(itemName, &id, &manager1);
            LOG_INFOS("ret %x id %d  manager %p", ret2, id, manager1);
            LOG_INFOS(" use cache %d ", manager->useCache);
            LOG_INFOS("list size %d ", manager->_list.size());
            LOG_INFOS("map size %d ", manager->_map->size());
            LOG_INFOS(" segments %d %x", manager->segments, offsetof(bisqueBase::util::GNP::NtyManager, segments));
            cacheDescriptor = nullptr;
        }
        LOG_INFOS("ret %d id %d  manager %p", ret, id, manager);
    }
    LOG_INFOS("ret %d ", sizeof(std::list<void*>));

    _frida_log("Initiaized ok ");
    return 0;
}

int testCacheManager(unsigned char* base, const char* datadir ) {

    const char* itemName = "opening_scroll_b.png";

    bisqueBase::util::GNP::NtyAPU apu;
    apu.set(itemName);

    auto *globalNtyPool = bisqueBase::util::GlobalNtyPool::instance();
    LOG_INFOS("globalNtyPool %p %d", globalNtyPool, globalNtyPool->getAttachQueueCount());

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
        }
    }

    LOG_INFOS("ret %d ", sizeof(std::list<void*>));

    _frida_log("Initiaized ok ");
    return 0;
}


extern "C" int __attribute__((visibility("default"))) init(unsigned char* base, const char* datadir ) {
    testManager();
    return 0;
}

