import { randomUUID } from 'node:crypto';

// Small PostgREST test double. No network or production credentials are used.
export function createMemoryDb(seed = []) {
  const rows = structuredClone(seed);
  return {
    rows,
    from() {
      let filters = [], orders = [], bounds, operation, payload, columns = '*', single = false;
      const query = {
        select(value = '*') { columns = value; return query; },
        eq(key, value) { filters.push(row => row[key] === value); return query; },
        ilike(key, value) { const needle = value.slice(1, -1).replace(/\\([\\%_])/g, '$1').toLocaleLowerCase('az'); filters.push(row => row[key].toLocaleLowerCase('az').includes(needle)); return query; },
        order(key, options = {}) { orders.push([key, options.ascending !== false]); return query; },
        range(start, end) { bounds = [start, end + 1]; return query; },
        maybeSingle() { single = true; return query; },
        single() { single = true; return query; },
        insert(value) { operation = 'insert'; payload = value; return query; },
        update(value) { operation = 'update'; payload = value; return query; },
        delete() { operation = 'delete'; return query; },
        then(resolve, reject) {
          try {
            let selected = rows.filter(row => filters.every(filter => filter(row)));
            if ((operation === 'insert' || operation === 'update') && rows.some(row => row.slug === payload.slug && (operation === 'insert' || !selected.includes(row)))) {
              return Promise.resolve({ data: null, error: { code: '23505' } }).then(resolve, reject);
            }
            if (operation === 'insert') {
              const row = { id: randomUUID(), created_at: new Date().toISOString(), updated_at: new Date().toISOString(), ...payload };
              rows.push(row); selected = [row];
            }
            if (operation === 'update') selected.forEach(row => Object.assign(row, payload));
            if (operation === 'delete') selected.forEach(row => rows.splice(rows.indexOf(row), 1));
            selected.sort((a, b) => {
              for (const [key, asc] of orders) { if (a[key] !== b[key]) return (a[key] > b[key] ? 1 : -1) * (asc ? 1 : -1); }
              return 0;
            });
            const count = selected.length;
            if (bounds) selected = selected.slice(...bounds);
            const data = selected.map(row => columns === '*' ? { ...row } : Object.fromEntries(columns.split(',').map(key => [key, row[key]])));
            return Promise.resolve({ data: single ? data[0] || null : data, count, error: null }).then(resolve, reject);
          } catch (error) { return Promise.reject(error).then(resolve, reject); }
        },
      };
      return query;
    },
  };
}
