#ifndef HAKC_DEFS_H
#define HAKC_DEFS_H

#define HAKC_PREPEND ".hakc."

const char *const hakc_section_names[] = {
	HAKC_PREPEND "SILVER_CLIQUE",  HAKC_PREPEND "GREEN_CLIQUE",
	HAKC_PREPEND "RED_CLIQUE",     HAKC_PREPEND "ORANGE_CLIQUE",
	HAKC_PREPEND "YELLOW_CLIQUE",  HAKC_PREPEND "PURPLE_CLIQUE",
	HAKC_PREPEND "BLUE_CLIQUE",    HAKC_PREPEND "GREY_CLIQUE",
	HAKC_PREPEND "PINK_CLIQUE",    HAKC_PREPEND "BROWN_CLIQUE",
	HAKC_PREPEND "WHITE_CLIQUE",   HAKC_PREPEND "BLACK_CLIQUE",
	HAKC_PREPEND "TEAL_CLIQUE",    HAKC_PREPEND "VIOLET_CLIQUE",
	HAKC_PREPEND "CRIMSON_CLIQUE", HAKC_PREPEND "GOLD_CLIQUE"
};
EXPORT_SYMBOL(hakc_section_names);

const char *const hakc_pcpu_section_names[] = {
	HAKC_PREPEND "SILVER_CLIQUE" ".data..percpu",
	HAKC_PREPEND "GREEN_CLIQUE" ".data..percpu",
	HAKC_PREPEND "RED_CLIQUE" ".data..percpu",
	HAKC_PREPEND "ORANGE_CLIQUE" ".data..percpu",
	HAKC_PREPEND "YELLOW_CLIQUE" ".data..percpu",
	HAKC_PREPEND "PURPLE_CLIQUE" ".data..percpu",
	HAKC_PREPEND "BLUE_CLIQUE" ".data..percpu",
	HAKC_PREPEND "GREY_CLIQUE" ".data..percpu",
	HAKC_PREPEND "PINK_CLIQUE" ".data..percpu",
	HAKC_PREPEND "BROWN_CLIQUE" ".data..percpu",
	HAKC_PREPEND "WHITE_CLIQUE" ".data..percpu",
	HAKC_PREPEND "BLACK_CLIQUE" ".data..percpu",
	HAKC_PREPEND "TEAL_CLIQUE" ".data..percpu",
	HAKC_PREPEND "VIOLET_CLIQUE" ".data..percpu",
	HAKC_PREPEND "CRIMSON_CLIQUE" ".data..percpu",
	HAKC_PREPEND "GOLD_CLIQUE" ".data..percpu"
};
EXPORT_SYMBOL(hakc_pcpu_section_names);

const char *const hakc_ro_after_init_section_names[] = {
	HAKC_PREPEND "SILVER_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "GREEN_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "RED_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "ORANGE_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "YELLOW_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "PURPLE_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "BLUE_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "GREY_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "PINK_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "BROWN_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "WHITE_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "BLACK_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "TEAL_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "VIOLET_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "CRIMSON_CLIQUE" ".data..ro_after_init",
	HAKC_PREPEND "GOLD_CLIQUE" ".data..ro_after_init"
};
EXPORT_SYMBOL(hakc_ro_after_init_section_names);

#define for_each_hakc_color(idx, color)                                        \
	for (idx = 0, color = START_CLIQUE; idx < HAKC_COLOR_COUNT;            \
	     idx++, color++)

#endif //HAKC_DEFS_H
