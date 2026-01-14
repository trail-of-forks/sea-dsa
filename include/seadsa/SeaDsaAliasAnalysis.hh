// ==- SeaDsaAliasAnalysis.hh - DSA-based Alias Analysis  ==//

#pragma once

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

#include "seadsa/Graph.hh"

#include <memory>

namespace llvm {
class CallGraph;
class Function;
class MemoryLocation;
class TargetLibraryInfoWrapper;
} // namespace llvm

namespace seadsa {

class AllocWrapInfo;
class DsaLibFuncInfo;
class BottomUpTopDownGlobalAnalysis;

template <typename T> class SeaDsaAAResultBase {
public:
  SeaDsaAAResultBase() = default;
  SeaDsaAAResultBase(SeaDsaAAResultBase &&) = default;
  SeaDsaAAResultBase &operator=(SeaDsaAAResultBase &&) = default;
  llvm::AliasResult alias(const llvm::MemoryLocation &,
                          const llvm::MemoryLocation &, llvm::AAQueryInfo &) {
    return llvm::AliasResult::MayAlias;
  }
};

class SeaDsaAAResult : public SeaDsaAAResultBase<SeaDsaAAResult> {
  using Base = SeaDsaAAResultBase<SeaDsaAAResult>;
  friend Base;

public:
  explicit SeaDsaAAResult(llvm::TargetLibraryInfoWrapperPass &tliWrapper,
                          AllocWrapInfo &AWI, DsaLibFuncInfo &dlfi);

  SeaDsaAAResult(SeaDsaAAResult &&RHS);
  ~SeaDsaAAResult();

  bool invalidate(llvm::Function &F, const llvm::PreservedAnalyses &,
                  llvm::FunctionAnalysisManager::Invalidator &) {
    return false;
  }

  llvm::AliasResult alias(const llvm::MemoryLocation &,
                          const llvm::MemoryLocation &, llvm::AAQueryInfo &,
                          const llvm::Instruction *CtxI);
  llvm::AliasResult alias(const llvm::MemoryLocation &,
                          const llvm::MemoryLocation &, llvm::AAQueryInfo &);

  llvm::ModRefInfo getModRefInfoMask(const llvm::MemoryLocation &,
                                     llvm::AAQueryInfo &, bool) {
    return llvm::ModRefInfo::ModRef;
  }
  llvm::ModRefInfo getArgModRefInfo(const llvm::CallBase &, unsigned) {
    return llvm::ModRefInfo::ModRef;
  }
  llvm::ModRefInfo getArgModRefInfo(const llvm::CallBase *Call,
                                    unsigned ArgIdx) {
    if (!Call) return llvm::ModRefInfo::ModRef;
    return getArgModRefInfo(*Call, ArgIdx);
  }
  llvm::MemoryEffects getMemoryEffects(const llvm::CallBase &,
                                       llvm::AAQueryInfo &) {
    return llvm::MemoryEffects::unknown();
  }
  llvm::MemoryEffects getMemoryEffects(const llvm::CallBase *Call,
                                       llvm::AAQueryInfo &AAQI) {
    if (!Call) return llvm::MemoryEffects::unknown();
    return getMemoryEffects(*Call, AAQI);
  }
  llvm::MemoryEffects getMemoryEffects(const llvm::Function &) {
    return llvm::MemoryEffects::unknown();
  }
  llvm::MemoryEffects getMemoryEffects(const llvm::Function *F) {
    if (!F) return llvm::MemoryEffects::unknown();
    return getMemoryEffects(*F);
  }
  llvm::ModRefInfo getModRefInfo(const llvm::CallBase &,
                                 const llvm::MemoryLocation &,
                                 llvm::AAQueryInfo &) {
    return llvm::ModRefInfo::ModRef;
  }
  llvm::ModRefInfo getModRefInfo(const llvm::CallBase *Call,
                                 const llvm::MemoryLocation &Loc,
                                 llvm::AAQueryInfo &AAQI) {
    if (!Call) return llvm::ModRefInfo::ModRef;
    return getModRefInfo(*Call, Loc, AAQI);
  }
  llvm::ModRefInfo getModRefInfo(const llvm::CallBase &, const llvm::CallBase &,
                                 llvm::AAQueryInfo &) {
    return llvm::ModRefInfo::ModRef;
  }
  llvm::ModRefInfo getModRefInfo(const llvm::CallBase *Call1,
                                 const llvm::CallBase *Call2,
                                 llvm::AAQueryInfo &AAQI) {
    if (!Call1 || !Call2) return llvm::ModRefInfo::ModRef;
    return getModRefInfo(*Call1, *Call2, AAQI);
  }

private:
  llvm::TargetLibraryInfoWrapperPass &m_tliWrapper;
  const llvm::DataLayout *m_dl;
  AllocWrapInfo &m_awi;
  DsaLibFuncInfo &m_dlfi;
  std::unique_ptr<Graph::SetFactory> m_fac; // node factory for seadsa
  std::unique_ptr<llvm::CallGraph> m_cg;
  std::unique_ptr<BottomUpTopDownGlobalAnalysis> m_dsa;
};

class SeaDsaAAWrapperPass : public llvm::ImmutablePass {

  std::unique_ptr<SeaDsaAAResult> Result;

public:
  using AnalysisUsage = llvm::AnalysisUsage;
  static char ID;

  SeaDsaAAWrapperPass();

  SeaDsaAAResult &getResult() { return *Result; }
  const SeaDsaAAResult &getResult() const { return *Result; }

  void initializePass() override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;
};

llvm::ImmutablePass *createSeaDsaAAWrapperPass();
} // namespace seadsa
