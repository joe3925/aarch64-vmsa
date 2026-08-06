use crate::address::{Level, TranslationGranule};
use crate::descriptor::{DescriptorFormat, DescriptorLayout, HasLayout};
use crate::regime::{LayoutOf, StageOf, TableFieldsOf, TranslationRegime};
use crate::table::{AccessError, TableShape, TableTransition};
use crate::translation::walk::WalkInputAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TablePlanContext<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    parent: TableShape<F, G>,
    target_leaf: Level,
    input: WalkInputAddr,
}

impl<F, G> TablePlanContext<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn new(parent: TableShape<F, G>, target_leaf: Level, input: WalkInputAddr) -> Self {
        Self {
            parent,
            target_leaf,
            input,
        }
    }

    pub const fn parent(self) -> TableShape<F, G> {
        self.parent
    }

    pub const fn target_leaf(self) -> Level {
        self.target_leaf
    }

    pub const fn input(self) -> WalkInputAddr {
        self.input
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TablePlan<F, G, A>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    child_shape: TableShape<F, G>,
    fields: A,
}

impl<F, G, A> TablePlan<F, G, A>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn new(child_shape: TableShape<F, G>, fields: A) -> Self {
        Self {
            child_shape,
            fields,
        }
    }

    pub const fn child_shape(&self) -> TableShape<F, G> {
        self.child_shape
    }

    pub fn into_fields(self) -> A {
        self.fields
    }
}

pub trait TablePlanProvider<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    fn plan_table(
        &mut self,
        context: TablePlanContext<F, G>,
    ) -> Result<TablePlan<F, G, TableFieldsOf<F, R, G>>, AccessError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepByOneTablePlan<A> {
    fields: A,
}

impl<A> StepByOneTablePlan<A> {
    pub const fn new(fields: A) -> Self {
        Self { fields }
    }
}

impl<F, R, G> TablePlanProvider<F, R, G> for StepByOneTablePlan<TableFieldsOf<F, R, G>>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    fn plan_table(
        &mut self,
        context: TablePlanContext<F, G>,
    ) -> Result<TablePlan<F, G, TableFieldsOf<F, R, G>>, AccessError> {
        let parent = context.parent();
        let child_level = parent.level().next();
        let child_shape = TableShape::new(child_level, 1)?;
        TableTransition::new(parent, child_shape)?;

        Ok(TablePlan::new(child_shape, self.fields))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedSklTablePlan<A> {
    fields: A,
    max_table_bytes: u64,
}

impl<A> BoundedSklTablePlan<A> {
    pub const fn new(fields: A, max_table_bytes: u64) -> Self {
        Self {
            fields,
            max_table_bytes,
        }
    }
}

impl<F, R, G> TablePlanProvider<F, R, G> for BoundedSklTablePlan<TableFieldsOf<F, R, G>>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    fn plan_table(
        &mut self,
        context: TablePlanContext<F, G>,
    ) -> Result<TablePlan<F, G, TableFieldsOf<F, R, G>>, AccessError> {
        choose_table_plan::<F, R, G, _>(context, self.max_table_bytes, self.fields)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaxSklTablePlan<A> {
    fields: A,
}

impl<A> MaxSklTablePlan<A> {
    pub const fn new(fields: A) -> Self {
        Self { fields }
    }
}

impl<F, R, G> TablePlanProvider<F, R, G> for MaxSklTablePlan<TableFieldsOf<F, R, G>>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    fn plan_table(
        &mut self,
        context: TablePlanContext<F, G>,
    ) -> Result<TablePlan<F, G, TableFieldsOf<F, R, G>>, AccessError> {
        choose_table_plan::<F, R, G, _>(context, u64::MAX, self.fields)
    }
}

fn choose_table_plan<F, R, G, A>(
    context: TablePlanContext<F, G>,
    max_table_bytes: u64,
    fields: A,
) -> Result<TablePlan<F, G, A>, AccessError>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: Copy,
{
    let parent = context.parent();
    let max_step = context.target_leaf().distance_from(parent.level()).ok_or(
        AccessError::InvalidTableLevel {
            root_level: parent.level(),
            level: context.target_leaf(),
            final_level: F::FINAL_LEVEL,
        },
    )?;

    let mut step = max_step;
    while step > 0 {
        let child_level = Level::new(parent.level().as_i8() + step as i8);
        let child_shape = match TableShape::new(child_level, step) {
            Ok(shape) => shape,
            Err(_) => {
                step -= 1;
                continue;
            }
        };
        let transition = match TableTransition::new(parent, child_shape) {
            Ok(transition) => transition,
            Err(_) => {
                step -= 1;
                continue;
            }
        };
        let layout = child_shape.alloc_layout()?;

        if layout.bytes() <= max_table_bytes
            && <LayoutOf<F, R, G> as DescriptorLayout<StageOf<R>, G>>::supports_table_transition(
                transition,
            )
        {
            return Ok(TablePlan::new(child_shape, fields));
        }

        step -= 1;
    }

    Err(AccessError::InvalidTableLevelStep { step: max_step })
}
