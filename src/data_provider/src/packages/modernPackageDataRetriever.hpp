/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MODERN_PACKAGE_DATA_RETRIEVER_HPP
#define _MODERN_PACKAGE_DATA_RETRIEVER_HPP

#include "json.hpp"
#include "sharedDefs.h"
#include <functional>
#include <map>
#include <unordered_set>

#if defined(HAS_STDFILESYSTEM) && HAS_STDFILESYSTEM==true
#include "packages/packagesNPM.hpp"
#include "packages/packagesPYPI.hpp"
#else
class PYPI
{
    public:
        void getPackages(const std::set<std::string>& /*paths*/, std::function<void(nlohmann::json&)> /*callback*/, const std::unordered_set<std::string>& /*excludePaths*/ = {});
};
class NPM
{
    public:
        void getPackages(const std::set<std::string>& /*paths*/, std::function<void(nlohmann::json&)> /*callback*/);
};
#endif

template <bool>
class ModernFactoryPackagesCreator final
{
    public:
        static void getPackages(const std::map<std::string, std::set<std::string>>& /*paths*/, std::function<void(nlohmann::json&)> /*callback*/, const std::unordered_set<std::string>& /*excludePaths*/ = {})
        {
        }
};

// Standard template to extract package information in fully compatible Linux
// systems
template <>
class ModernFactoryPackagesCreator<true> final
{
    public:
        static void getPackages(const std::map<std::string, std::set<std::string>>& paths, std::function<void(nlohmann::json&)> callback, const std::unordered_set<std::string>& excludePaths = {})
        {
            auto cbCopy {callback};
            PYPI().getPackages(paths.at("PYPI"), std::move(callback), excludePaths);
            NPM().getPackages(paths.at("NPM"), std::move(cbCopy));
        }
};

#endif  // _MODERN_PACKAGE_DATA_RETRIEVER_HPP
