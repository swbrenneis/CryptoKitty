#ifndef REFERENCEMANAGER_H_INCLUDED
#define REFERENCEMANAGER_H_INCLUDED

#include <map>
#include <mutex>

namespace CK {
    class JNIReference;
}

class ReferenceManager {

    public:
        ReferenceManager();
        ~ReferenceManager();

    private:
        ReferenceManager(const ReferenceManager& other);
        ReferenceManager& operator= (const ReferenceManager& other);

    public:
        long addRef(CK::JNIReference *ref);
        void deleteRef(long index);
        CK::JNIReference *getRef(long index) const;
        static ReferenceManager *instance();

    private:
        static ReferenceManager *theInstance;

        long refIndex;
        struct Reference {
            CK::JNIReference *ref;
            bool deleted;
        };
        typedef std::map<long, Reference> ReferenceMap;
        typedef ReferenceMap::iterator RefIter;
        typedef ReferenceMap::const_iterator RefConstIter;
        ReferenceMap references;
        std::mutex refMutex;

};

#endif // REFERENCEMANAGER_H_INCLUDED

