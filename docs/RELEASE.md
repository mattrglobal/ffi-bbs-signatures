# Stable Releases

To create a stable release follow the following steps

1. Checkout the head of master `git checkout master && git pull`
2. Create a new release branch from master e.g `release`
3. Install the dependencies `yarn install --frozen-lockfile`
4. Build the package `yarn build`
5. Test the package `yarn test`
7. Run `yarn version:release`, note by default this will do a minor package release as we are pre the `1.0.0` release
8. Observe the correctly incremented change to the `package.json` and the new entry in `CHANGELOG.md` along with the
   newly created commit
9. Push the release branch including the newly created tags `git push origin release --tags`
10. Open a pull request for the release, once approvals have been sought, merge the pull request using squash,
    preserving the commit message as `chore(release): publish [skip ci]`
11. Observe the triggering of the `/.github/workflows/release.yaml`

The resulting release will publish as a github release.