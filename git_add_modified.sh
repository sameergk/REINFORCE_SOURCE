git status
echo "========= START Adding Modified Files ========================"
git status | awk '$1 == "modified:" { print ($2)}'| xargs git add
git status | awk '$1 == "deleted:" { print ($2)}'| xargs git rm
echo "========= END Adding Modified Files ========================"
