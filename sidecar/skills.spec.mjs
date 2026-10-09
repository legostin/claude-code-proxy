// node --test sidecar/skills.spec.mjs
// The skills' rule recipes are rules the engine takes: every JSON block of a
// skill that holds an "id" validates.

import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { describeRule, ruleErrors } from '../shared/rules.mjs'

const skills = join(dirname(fileURLToPath(import.meta.url)), '..', 'skills')

describe('the skills', () => {
  for (const name of readdirSync(skills)) {
    const text = readFileSync(join(skills, name, 'SKILL.md'), 'utf8')
    test(`${name}: names itself and says when to use it`, () => {
      const front = /^---\nname: ([\w-]+)\ndescription: (.+)\n---\n/.exec(text)
      assert.ok(front, 'frontmatter with name and description')
      assert.equal(front[1], name)
      assert.ok(front[2].startsWith('Use when'), 'the description says when')
    })
    const blocks = [...text.matchAll(/```json\n([\s\S]*?)```/g)].map(match => match[1])
    for (const [i, block] of blocks.entries()) {
      const value = JSON.parse(block)
      if (typeof value.id !== 'string') continue
      test(`${name}: the rule ${value.id} validates`, () => {
        assert.deepEqual(ruleErrors(value), [], `block ${i + 1}`)
        assert.ok(describeRule(value).length > 10)
      })
    }
  }
})
