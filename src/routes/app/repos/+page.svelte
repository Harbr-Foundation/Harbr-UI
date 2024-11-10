<script>
  import { 
    Search,
    GitFork,
    Star,
    Clock,
    Filter,
    Lock,
    Globe2
  } from 'lucide-svelte';
  import { onMount } from 'svelte';

  let searchQuery = '';
  let showFilters = false;
  
  // Initialize repositories as empty array
  let repositories = [];
  
  // Filter states
  let selectedType = 'all';
  let selectedLanguage = 'all';
  let selectedSort = 'updated';

  const languages = [
    { name: 'All', value: 'all' },
    { name: 'TypeScript', value: 'typescript', color: '#2b7489' },
    { name: 'JavaScript', value: 'javascript', color: '#f1e05a' },
    { name: 'Python', value: 'python', color: '#3572A5' },
    { name: 'Rust', value: 'rust', color: '#dea584' },
    { name: 'Go', value: 'go', color: '#00ADD8' }
  ];

  // Move fetch inside onMount
  onMount(async () => {
    try {
      const response = await fetch('/api/repo.json');
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      repositories = await response.json();
    } catch (error) {
      console.error('Error:', error);
      // Optionally set an error state here
    }
  });

  // Filter and sort repositories
  $: filteredRepos = repositories
    ? repositories.filter(repo => {
        const matchesSearch = repo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            (repo.description && repo.description.toLowerCase().includes(searchQuery.toLowerCase()));
        const matchesType = selectedType === 'all' ? true :
                           selectedType === 'public' ? !repo.isPrivate :
                           repo.isPrivate;
        const matchesLanguage = selectedLanguage === 'all' ? true :
                               repo.language && repo.language.toLowerCase() === selectedLanguage;
        return matchesSearch && matchesType && matchesLanguage;
      })
      .sort((a, b) => {
        switch (selectedSort) {
          case 'stars':
            return (b.stars || 0) - (a.stars || 0);
          case 'name':
            return a.name.localeCompare(b.name);
          case 'updated':
          default:
            return b.lastUpdated.localeCompare(a.lastUpdated);
        }
      })
    : [];
</script>

<!-- Page Header -->
<div class="flex flex-col gap-6">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-semibold text-white">Repositories</h1>
    <a
      href="/app/new"
      class="px-4 py-2 bg-emerald-500 text-black font-medium rounded-lg hover:bg-emerald-400 transition-colors"
    >
      New
    </a>
  </div>

  <!-- Search and Filters -->
  <div class="flex items-center space-x-4 mb-6">
    <div class="relative flex-1 max-w-2xl">
      <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <Search 
          size={20}
          class="text-zinc-400" 
        />
      </div>
      <input
        type="text"
        bind:value={searchQuery}
        placeholder="Find a repository..."
        class="w-full h-10 pl-10 pr-4 bg-black border border-zinc-800 rounded-md text-white placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700 focus:ring-1 focus:ring-zinc-700"
      >
    </div>

    <div class="flex gap-2">
      <div class="relative">
        <button
          class="h-10 px-4 bg-black border border-zinc-800 rounded-md text-zinc-400 hover:text-white transition-colors flex items-center gap-2"
          on:click={() => showFilters = !showFilters}
        >
          <Filter size={16} />
          Filters
        </button>
        
        {#if showFilters}
          <div class="absolute right-0 mt-2 w-64 bg-black border border-zinc-800 rounded-lg shadow-xl z-10 p-4">
            <div class="space-y-4">
              <!-- Type filter -->
              <div>
                <label class="text-sm font-medium text-zinc-400">Type</label>
                <div class="mt-2 flex gap-2">
                  {#each ['all', 'public', 'private'] as type}
                    <button
                      class="px-3 py-1 text-sm rounded-md {selectedType === type ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/50' : 'bg-zinc-800/50 text-zinc-400 border-transparent'} border"
                      on:click={() => selectedType = type}
                    >
                      {type.charAt(0).toUpperCase() + type.slice(1)}
                    </button>
                  {/each}
                </div>
              </div>

              <!-- Language filter -->
              <div>
                <label class="text-sm font-medium text-zinc-400">Language</label>
                <select
                  bind:value={selectedLanguage}
                  class="mt-2 w-full h-9 px-3 bg-zinc-900 border border-zinc-800 rounded-md text-zinc-300"
                >
                  {#each languages as language}
                    <option value={language.value.toLowerCase()}>{language.name}</option>
                  {/each}
                </select>
              </div>
            </div>
          </div>
        {/if}
      </div>

      <select
        bind:value={selectedSort}
        class="h-10 px-4 bg-black border border-zinc-800 rounded-md text-zinc-400 hover:text-white transition-colors appearance-none"
      >
        <option value="updated">Last updated</option>
        <option value="stars">Most stars</option>
        <option value="name">Name</option>
      </select>
    </div>
  </div>

  <!-- Repository List -->
  <div class="grid gap-4">
    {#each filteredRepos as repo}
      <div class="p-4 bg-zinc-900/50 rounded-lg border border-zinc-800 hover:border-emerald-500/50 transition-all">
        <div class="flex items-start justify-between">
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              {#if repo.isPrivate}
                <Lock size={16} class="text-zinc-500" />
              {:else}
                <Globe2 size={16} class="text-zinc-500" />
              {/if}
              <a
                href={`/app/repos/${repo.name}`}
                class="text-lg font-medium text-white hover:text-emerald-400 transition-colors truncate"
              >
                {repo.name}
              </a>
            </div>
            <p class="mt-1 text-sm text-zinc-400">{repo.description || ''}</p>
            
            <!-- Topics -->
            {#if repo.topics && repo.topics.length > 0}
              <div class="mt-3 flex flex-wrap gap-2">
                {#each repo.topics as topic}
                  <span class="px-2 py-1 text-xs rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    {topic}
                  </span>
                {/each}
              </div>
            {/if}

            <!-- Meta info -->
            <div class="mt-4 flex items-center gap-4 text-sm">
              {#if repo.language}
                <div class="flex items-center gap-1">
                  <span class="w-3 h-3 rounded-full" style="background-color: {repo.languageColor || '#808080'}"></span>
                  <span class="text-zinc-400">{repo.language}</span>
                </div>
              {/if}
              {#if repo.stars > 0}
                <div class="flex items-center gap-1 text-zinc-400">
                  <Star size={16} />
                  {repo.stars}
                </div>
              {/if}
              {#if repo.forks > 0}
                <div class="flex items-center gap-1 text-zinc-400">
                  <GitFork size={16} />
                  {repo.forks}
                </div>
              {/if}
              <div class="flex items-center gap-1 text-zinc-400">
                <Clock size={16} />
                {repo.lastUpdated}
              </div>
            </div>
          </div>
        </div>
      </div>
    {/each}
  </div>
</div>