/**
 * Demo seed — creates a login account + published apps so you can browse the UI.
 *
 * Run:  npx tsx prisma/seed-demo.ts
 *
 * Demo credentials:
 *   Email:    demo@imagine.com
 *   Password: demo1234
 */

import bcrypt from 'bcryptjs'
import { PrismaClient, AppStatus, UserRole } from '@prisma/client'

const db = new PrismaClient()

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

const CATEGORIES = [
  { name: 'AI Tools',     slug: 'ai-tools',     description: 'Artificial intelligence and machine learning applications', sortOrder: 0 },
  { name: 'Analytics',    slug: 'analytics',    description: 'Data analysis, dashboards, and business intelligence',      sortOrder: 1 },
  { name: 'Finance',      slug: 'finance',       description: 'Budgeting, investing, and financial management',            sortOrder: 2 },
  { name: 'Fitness',      slug: 'fitness',       description: 'Workouts, training plans, and physical wellness',           sortOrder: 3 },
  { name: 'Games',        slug: 'games',         description: 'Games and interactive entertainment',                       sortOrder: 4 },
  { name: 'Health',       slug: 'health',        description: 'Nutrition, mental wellness, and healthcare tools',          sortOrder: 5 },
  { name: 'Productivity', slug: 'productivity',  description: 'Focus, task management, and workflow tools',                sortOrder: 6 },
  { name: 'Education',    slug: 'education',     description: 'Learning, courses, and skill building',                     sortOrder: 7 },
]

const APPS = [
  {
    slug: 'prompt-wizard',
    name: 'Prompt Wizard',
    tagline: 'Craft perfect AI prompts in seconds',
    description: 'Prompt Wizard helps you write, refine, and organize prompts for any AI model. Save your best prompts, share templates with the community, and level up your AI game. Works with GPT-4, Claude, Gemini, and more.',
    categorySlug: 'ai-tools',
    launchUrl: 'https://example.com/prompt-wizard',
    primaryColor: '#0EA5E9',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=promptwizard&backgroundColor=0ea5e9',
    reviewCount: 24,
  },
  {
    slug: 'calorie-copilot',
    name: 'Calorie Copilot',
    tagline: 'AI-powered nutrition tracking, zero effort',
    description: 'Just describe what you ate — Calorie Copilot uses AI to instantly log macros, estimate portions, and suggest balanced meals for the rest of your day. No barcode scanning, no manual entry.',
    categorySlug: 'health',
    launchUrl: 'https://example.com/calorie-copilot',
    primaryColor: '#10B981',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=caloriecopilot&backgroundColor=10b981',
    reviewCount: 18,
  },
  {
    slug: 'dashboard-gpt',
    name: 'Dashboard GPT',
    tagline: 'Turn your data into beautiful insights',
    description: 'Connect any CSV or spreadsheet and ask questions in plain English. Dashboard GPT generates charts, summaries, and trend analysis automatically. Share dashboards with one click.',
    categorySlug: 'analytics',
    launchUrl: 'https://example.com/dashboard-gpt',
    primaryColor: '#6366F1',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=dashboardgpt&backgroundColor=6366f1',
    reviewCount: 15,
  },
  {
    slug: 'word-quest',
    name: 'Word Quest',
    tagline: 'Vocabulary games powered by AI',
    description: 'An adaptive word game that learns your vocabulary level and challenges you with new words every day. Earn XP, unlock achievements, and compete with friends on the leaderboard.',
    categorySlug: 'games',
    launchUrl: 'https://example.com/word-quest',
    primaryColor: '#F59E0B',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=wordquest&backgroundColor=f59e0b',
    reviewCount: 11,
  },
  {
    slug: 'budget-buddy',
    name: 'Budget Buddy',
    tagline: 'Smart personal finance without the spreadsheet',
    description: 'Budget Buddy connects to your bank data and uses AI to categorize expenses, flag unusual spending, and build a personalized savings plan. Get weekly digest emails with actionable tips.',
    categorySlug: 'finance',
    launchUrl: 'https://example.com/budget-buddy',
    primaryColor: '#14B8A6',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=budgetbuddy&backgroundColor=14b8a6',
    reviewCount: 9,
  },
  {
    slug: 'deepfocus',
    name: 'DeepFocus',
    tagline: 'Flow-state productivity timer with AI coaching',
    description: 'DeepFocus combines Pomodoro timers with AI insights. It learns when you do your best work, surfaces your peak hours, and nudges you back on track when you drift. Integrates with Notion and Linear.',
    categorySlug: 'productivity',
    launchUrl: 'https://example.com/deepfocus',
    primaryColor: '#8B5CF6',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=deepfocus&backgroundColor=8b5cf6',
    reviewCount: 7,
  },
  {
    slug: 'coach-ai',
    name: 'Coach AI',
    tagline: 'Personal workout plans built for you',
    description: 'Tell Coach AI your goals, available equipment, and schedule — it builds a weekly workout plan, tracks progress, and adjusts difficulty automatically. Includes form tips via video analysis.',
    categorySlug: 'fitness',
    launchUrl: 'https://example.com/coach-ai',
    primaryColor: '#EF4444',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=coachai&backgroundColor=ef4444',
    reviewCount: 5,
  },
  {
    slug: 'flashlearn',
    name: 'FlashLearn',
    tagline: 'AI flashcards from any text or PDF',
    description: 'Paste any article, textbook chapter, or PDF and FlashLearn auto-generates spaced-repetition flashcards. Study on any device and track your retention over time.',
    categorySlug: 'education',
    launchUrl: 'https://example.com/flashlearn',
    primaryColor: '#F97316',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=flashlearn&backgroundColor=f97316',
    reviewCount: 3,
  },
  {
    slug: 'stock-sage',
    name: 'Stock Sage',
    tagline: 'AI market summaries, plain and simple',
    description: 'Stock Sage scans financial news and earnings calls, then distills it into a 60-second daily briefing for your watchlist. No jargon, no noise — just what actually moved the market today.',
    categorySlug: 'finance',
    launchUrl: 'https://example.com/stock-sage',
    primaryColor: '#0284C7',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=stocksage&backgroundColor=0284c7',
    reviewCount: 2,
  },
  {
    slug: 'sleep-gpt',
    name: 'Sleep GPT',
    tagline: 'Understand and improve your sleep with AI',
    description: 'Log your sleep habits and Sleep GPT identifies patterns affecting your rest — late screens, caffeine timing, stress spikes. Get a personalized nightly wind-down routine and morning check-in.',
    categorySlug: 'health',
    launchUrl: 'https://example.com/sleep-gpt',
    primaryColor: '#A855F7',
    iconUrl: 'https://api.dicebear.com/8.x/shapes/svg?seed=sleepgpt&backgroundColor=a855f7',
    reviewCount: 1,
  },
]

const REVIEW_COMMENTS = [
  'This app is genuinely amazing. Changed the way I work every day.',
  'Super intuitive and fast. Exactly what I was looking for.',
  'Really solid. A few rough edges but the core experience is great.',
  'I use this every morning. Cannot imagine my routine without it now.',
  'The AI is surprisingly smart. Impressed by how well it understands context.',
  'Clean UI, works great on mobile too. Well done!',
  'Game changer for my workflow. 10/10 would recommend.',
  'Great concept and solid execution. Keep it up!',
  'Tried a dozen apps like this — this is the best one.',
  'Simple, fast, and it just works. Love it.',
]

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('\n🌱 Seeding demo data…\n')

  // 1. Categories
  console.log('📁 Categories…')
  const categoryMap = new Map<string, string>()
  for (const cat of CATEGORIES) {
    const c = await db.category.upsert({
      where:  { slug: cat.slug },
      update: { name: cat.name, description: cat.description, sortOrder: cat.sortOrder },
      create: cat,
    })
    categoryMap.set(cat.slug, c.id)
    console.log(`   ✓ ${cat.name}`)
  }

  // 2. Demo creator account
  console.log('\n👤 Demo user…')
  const passwordHash = await bcrypt.hash('demo1234', 10)
  const demoUser = await db.user.upsert({
    where:  { email: 'demo@imagine.com' },
    update: { passwordHash, role: UserRole.CREATOR },
    create: { email: 'demo@imagine.com', passwordHash, role: UserRole.CREATOR },
  })
  await db.creator.upsert({
    where:  { userId: demoUser.id },
    update: { displayName: 'Demo Creator', bio: 'Building awesome AI apps on Imagine.' },
    create: { userId: demoUser.id, displayName: 'Demo Creator', bio: 'Building awesome AI apps on Imagine.' },
  })
  const demoCreator = await db.creator.findUnique({ where: { userId: demoUser.id } })
  console.log('   ✓ demo@imagine.com / demo1234')

  // 3. Reviewer accounts (for generating reviews)
  console.log('\n👥 Reviewer accounts…')
  const reviewers: string[] = []
  const reviewerData = [
    { email: 'alice@imagine.com',   name: 'Alice Chen'   },
    { email: 'bob@imagine.com',     name: 'Bob Martinez' },
    { email: 'carol@imagine.com',   name: 'Carol Smith'  },
    { email: 'david@imagine.com',   name: 'David Park'   },
    { email: 'eva@imagine.com',     name: 'Eva Johnson'  },
  ]
  for (const r of reviewerData) {
    const hash = await bcrypt.hash('reviewer123', 8)
    const u = await db.user.upsert({
      where:  { email: r.email },
      update: {},
      create: { email: r.email, passwordHash: hash, role: UserRole.USER },
    })
    reviewers.push(u.id)
    console.log(`   ✓ ${r.name}`)
  }

  // 4. Apps + reviews
  console.log('\n🚀 Apps…')
  const now = new Date()
  for (const [idx, appData] of APPS.entries()) {
    const catId = categoryMap.get(appData.categorySlug)
    const publishedAt = new Date(now.getTime() - (APPS.length - idx) * 24 * 60 * 60 * 1000)

    const app = await db.app.upsert({
      where:  { slug: appData.slug },
      update: {
        name: appData.name, tagline: appData.tagline, description: appData.description,
        status: AppStatus.PUBLISHED, launchUrl: appData.launchUrl,
        primaryColor: appData.primaryColor, iconUrl: appData.iconUrl,
        categoryId: catId, publishedAt,
      },
      create: {
        slug: appData.slug, name: appData.name, tagline: appData.tagline,
        description: appData.description, status: AppStatus.PUBLISHED,
        launchUrl: appData.launchUrl, primaryColor: appData.primaryColor,
        iconUrl: appData.iconUrl, categoryId: catId, publishedAt,
        createdAt: publishedAt,
        creator: { connect: { id: demoCreator!.id } },
      },
    })

    // Delete existing reviews then recreate for idempotency
    await db.appReview.deleteMany({ where: { appId: app.id } })

    for (let i = 0; i < appData.reviewCount && i < reviewers.length * 5; i++) {
      const reviewerId = reviewers[i % reviewers.length]!
      // Each reviewer can only review once per app — skip duplicates
      const existing = await db.appReview.findUnique({
        where: { appId_userId: { appId: app.id, userId: reviewerId } },
      })
      if (existing) continue

      await db.appReview.create({
        data: {
          appId:   app.id,
          userId:  reviewerId,
          rating:  Math.max(3, 5 - Math.floor(i / reviewers.length)),
          comment: REVIEW_COMMENTS[(idx + i) % REVIEW_COMMENTS.length]!,
        },
      })
    }

    console.log(`   ✓ ${appData.name}  (${appData.reviewCount} reviews)`)
  }

  console.log('\n✅ Done!\n')
  console.log('  Login at http://localhost:3001/sign-in')
  console.log('  Email:    demo@imagine.com')
  console.log('  Password: demo1234\n')
}

main()
  .catch(e => { console.error(e); process.exit(1) })
  .finally(() => db.$disconnect())
