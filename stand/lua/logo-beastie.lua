--
-- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
--
-- Copyright (c) 2018 Kyle Evans <kevans@FreeBSD.org>
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--
-- $FreeBSD$
--

local drawer = require("drawer")

local beastie_color = {
"               \027[31m,        ,",
"              /(        )`",
"              \\ \\___   / |",
"              /- \027[37m_\027[31m  `-/  '",
"             (\027[37m/\\/ \\\027[31m \\   /\\",
"             \027[37m/ /   |\027[31m `    \\",
"             \027[34mO O   \027[37m) \027[31m/    |",
"             \027[37m`-^--'\027[31m`<     '",
"            (_.)  _  )   /",
"             `.___/`    /",
"               `-----' /",
"  \027[33m<----.\027[31m     __ / __   \\",
"  \027[33m<----|====\027[31mO)))\027[33m==\027[31m) \\) /\027[33m====|",
"  \027[33m<----'\027[31m    `--' `.__,' \\",
"               |        |",
"                \\       /       /\\",
"           \027[36m______\027[31m( (_  / \\______/",
"         \027[36m,'  ,-----'   |",
"         `--{__________)\027[37m"
}

drawer.addLogo("beastie", {
	requires_color = true,
	graphic = beastie_color,
})

return true
