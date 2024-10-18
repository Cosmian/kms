#!/bin/bash

# Pre-requisites:
    # sudo apt-get install texlive-full
    # wget https://github.com/jgm/pandoc/releases/download/2.17.1.1/pandoc-2.17.1.1-1-amd64.deb
    # sudo dpkg -i pandoc-2.17.1.1-1-amd64.deb
    # sudo apt-get install fonts-noto-mono fonts-noto pandoc-citeproc librsvg2-bin
    # pip install pydoc-markdown git+https://github.com/twardoch/mkdocs-combine.git mkdocs-kroki-plugin mkdocs-material pandoc-latex-admonition markdown-katex git+https://gitlab.com/myriacore/pandoc-kroki-filter.git
    # cargo install pandoc-katex

set -e

doc="user_guide"

root=$1
if [ -z "$1" ]
then
    root="."
fi

common_sed()
{
    args=$1
    file=$2
    os_version=$(uname)
    if [[ "Linux" == *"$os_version"* ]]; then
        # echo "Linux"
        sed -i "${args}" "$file"
    else
        # echo "Not Linux"
        sed -i '' "${args}" "$file"
    fi

}


root=$(dirname "$1")
script_dir=$(dirname "${BASH_SOURCE[0]}")
script_dir=$(cd "$(dirname "$script_dir")"; pwd -P)/$(basename "$script_dir")

eisvogel_template="${script_dir}/pandoc/eisvogel.tex"

# echo "$eisvogel_template"
# exit 0

# Merge .md files
# command added to build site directory to fix images displaying issue
pushd "${root}"
if [[ -f "mkdocs.yml" ]]
then
    echo "mkdocs.yml exists in folder ${doc}"

    # create site directory
    mkdocs build

    # merge .md files into one .pd file
    mkdocscombine -o "${doc}.pd"

    # Remove css classes added by mkdocscombine
    common_sed "s/{: .page-title}/ /g" "${doc}.pd"

    # TODO : Changes must be done in .md files not in .pd
    # Replace $`...`$ by $...$
    common_sed "s/$\`/$/g" "${doc}.pd"
    common_sed "s/\`\\$/$/g" "${doc}.pd"

    # Replace HTML by Pandoc syntax
    common_sed 's/<div class="admonition error">/::: {.admonition .error} :::/g' "${doc}.pd"
    common_sed 's/<div class="admonition info">/::: {.admonition .info} :::/g' "${doc}.pd"
    common_sed 's/<div class="admonition note">/::: {.admonition .note} :::/g' "${doc}.pd"
    common_sed 's/<div class="admonition important">/::: {.admonition .important} :::/g' "${doc}.pd"
    common_sed 's/<\/div>/:::::::::::::::::::::::::::::/g' "${doc}.pd"
    common_sed 's/<h4>/**/g' "${doc}.pd"
    common_sed 's/<\/h4>/**/g' "${doc}.pd"
    common_sed 's/<br>/\\/g' "${doc}.pd"

    # Replace markdown tab syntax for Pandoc
    grep -n '=== "' "${doc}.pd" | cut -f1 -d: | while read -r source ; do
        echo - "$source"
        common_sed "${source}s/===/#####\&nbsp;/g" "${doc}.pd"
        common_sed "${source}s/\"//g" "${doc}.pd"
    done

    # generate PDF
    pdf_title="${doc}"
    pandoc --citeproc --from markdown --template="${eisvogel_template}" includes.yml "${doc}.pd" -s  -o "${pdf_title}.pdf" --listings --pdf-engine=xelatex --filter pandoc-kroki #--filter pandoc-katex

    rm -r site/
else
 echo "no mkdocs.yml file in the $1 directory"
fi
popd
