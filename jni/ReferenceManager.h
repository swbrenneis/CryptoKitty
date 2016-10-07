#ifndef REFERENCEMANAGER_H_INCLUDED
#define REFERENCEMANAGER_H_INCLUDED

#include <map>

namespace CK {
    class JNIReference;
}

namespace cthread {
    class Mutex;
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
        cthread::Mutex *refMutex;

};

#endif // REFERENCEMANAGER_H_INCLUDED

