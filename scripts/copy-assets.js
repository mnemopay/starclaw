const fs=require('fs');fs.mkdirSync('dist/sandbox',{recursive:true});fs.copyFileSync('src/sandbox/runner.cjs','dist/sandbox/runner.cjs');console.log('copied runner.cjs');
