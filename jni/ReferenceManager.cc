#include "ReferenceManager.h"
#include <CryptoKitty-C/jni/JNIReference.h>

// The singlton.
ReferenceManager *ReferenceManager::theInstance = 0;

ReferenceManager::ReferenceManager()
: refIndex(100) {
}

ReferenceManager::~ReferenceManager() {
}

long ReferenceManager::addRef(CK::JNIReference *ref) {

    std::lock_guard<std::mutex> lock(refMutex);

    Reference reference;
    reference.ref = ref;
    reference.deleted = false;
    references[refIndex] = reference;
    return refIndex++;

}

void ReferenceManager::deleteRef(long index) {

    RefIter it = references.find(index);
    if (it != references.end() && !it->second.deleted) {
        it->second.deleted = true;
        delete it->second.ref;
    }

}

CK::JNIReference *ReferenceManager::getRef(long index) const {

    RefConstIter it = references.find(index);
    if (it != references.end() && !it->second.deleted) {
        return it->second.ref;
    }
    else {
        return 0;
    }

}

ReferenceManager *ReferenceManager::instance() {

    if (theInstance == 0) {
        theInstance = new ReferenceManager;
    }

    return theInstance;

}

